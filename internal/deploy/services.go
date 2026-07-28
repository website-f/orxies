package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"orxies/internal/agent"
	"orxies/internal/store"
)

// Creds is the (encrypted-at-rest) credential set for a service.
type Creds struct {
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
	DB   string `json:"db,omitempty"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	URL  string `json:"url,omitempty"` // external / redis
}

// ServiceName is the container + on-network DNS name for a service.
func ServiceName(name string) string { return "orxies-svc-" + safeName(name) }

// ProvisionService starts a managed service container (or records an
// external one) and stores its encrypted credentials.
func (m *Manager) ProvisionService(ctx context.Context, serviceID int64, logW io.Writer) error {
	svc, err := m.Store.GetService(serviceID)
	if err != nil {
		return err
	}
	if svc.Mode == "external" {
		svc.Status = "external"
		return m.Store.UpdateService(svc)
	}
	if m.Agent == nil {
		return errors.New("agent not configured — managed services need the orxies-agent")
	}
	spec, creds, err := engineSpec(svc)
	if err != nil {
		return err
	}
	m.storeCreds(svc, creds)

	_ = m.Agent.EnsureNetwork(ctx, NetworkName)
	name := ServiceName(svc.Name)
	_ = m.Agent.Remove(ctx, name) // clear any stale container with this name
	fmt.Fprintf(logW, "Starting %s service %q on the internal network...\n", svc.Engine, name)
	id, err := m.Agent.Run(ctx, spec)
	if err != nil {
		svc.Status = "failed"
		_ = m.Store.UpdateService(svc)
		return fmt.Errorf("start service: %w", err)
	}
	svc.ContainerID = id
	svc.Status = "running"
	if err := m.Store.UpdateService(svc); err != nil {
		return err
	}
	fmt.Fprintf(logW, "Service %q is up. Linked apps reach it at host %q.\n", svc.Name, name)
	return nil
}

// RemoveService stops+removes a managed service container and deletes the
// record. The data volume is intentionally left behind (safer default).
func (m *Manager) RemoveService(ctx context.Context, serviceID int64) error {
	svc, err := m.Store.GetService(serviceID)
	if err != nil {
		return err
	}
	if svc.Mode == "managed" && m.Agent != nil {
		_ = m.Agent.Remove(ctx, ServiceName(svc.Name))
	}
	return m.Store.DeleteService(serviceID)
}

func (m *Manager) storeCreds(svc *store.Service, c Creds) {
	b, _ := json.Marshal(c)
	if m.Secrets != nil {
		if enc, err := m.Secrets.Encrypt(string(b)); err == nil {
			svc.CredsEnc = enc
			return
		}
	}
	svc.CredsEnc = string(b)
}

func (m *Manager) decodeCreds(svc *store.Service) Creds {
	raw := svc.CredsEnc
	if m.Secrets != nil {
		if dec, err := m.Secrets.Decrypt(svc.CredsEnc); err == nil {
			raw = dec
		}
	}
	var c Creds
	_ = json.Unmarshal([]byte(raw), &c)
	return c
}

// SetExternalCreds encodes external connection info for storage.
func (m *Manager) SetExternalCreds(svc *store.Service, url string) {
	m.storeCreds(svc, Creds{URL: url})
}

// engineSpec returns the RunSpec + generated credentials for a managed
// service engine.
func engineSpec(svc *store.Service) (agent.RunSpec, Creds, error) {
	name := ServiceName(svc.Name)
	pass := randToken()
	switch svc.Engine {
	case "postgres":
		c := Creds{User: "orxies", Pass: pass, DB: "app", Host: name, Port: 5432}
		return agent.RunSpec{
			Name: name, Image: "postgres:16-alpine", Network: NetworkName,
			Unhardened: true, MemoryMB: 512,
			Env:     map[string]string{"POSTGRES_USER": c.User, "POSTGRES_PASSWORD": c.Pass, "POSTGRES_DB": c.DB},
			Volumes: map[string]string{name + "-data": "/var/lib/postgresql/data"},
		}, c, nil
	case "mysql":
		c := Creds{User: "orxies", Pass: pass, DB: "app", Host: name, Port: 3306}
		return agent.RunSpec{
			Name: name, Image: "mysql:8", Network: NetworkName,
			Unhardened: true, MemoryMB: 512,
			Env: map[string]string{
				"MYSQL_ROOT_PASSWORD": randToken(), "MYSQL_DATABASE": c.DB,
				"MYSQL_USER": c.User, "MYSQL_PASSWORD": c.Pass,
			},
			Volumes: map[string]string{name + "-data": "/var/lib/mysql"},
		}, c, nil
	case "redis":
		c := Creds{Host: name, Port: 6379, URL: "redis://" + name + ":6379"}
		return agent.RunSpec{
			Name: name, Image: "redis:7-alpine", Network: NetworkName,
			Unhardened: true, MemoryMB: 256,
			Volumes: map[string]string{name + "-data": "/data"},
		}, c, nil
	default:
		return agent.RunSpec{}, Creds{}, fmt.Errorf("unknown engine %q", svc.Engine)
	}
}

// envForProject assembles the container environment: custom project vars
// plus the connection env for every linked service.
func (m *Manager) envForProject(p *store.Project, logW io.Writer) map[string]string {
	env := map[string]string{}
	if p.EnvEnc != "" && m.Secrets != nil {
		if dec, err := m.Secrets.Decrypt(p.EnvEnc); err == nil {
			var kv map[string]string
			if json.Unmarshal([]byte(dec), &kv) == nil {
				for k, v := range kv {
					env[k] = v
				}
			}
		}
	}
	svcs, _ := m.Store.LinkedServices(p.ID)
	for _, svc := range svcs {
		for k, v := range serviceEnv(svc, m.decodeCreds(svc)) {
			env[k] = v
		}
		if logW != nil {
			fmt.Fprintf(logW, "Injected %s credentials for service %q\n", svc.Engine, svc.Name)
		}
	}
	return env
}

func serviceEnv(svc *store.Service, c Creds) map[string]string {
	switch svc.Engine {
	case "postgres":
		url := c.URL
		if url == "" {
			url = fmt.Sprintf("postgresql://%s:%s@%s:%d/%s", c.User, c.Pass, c.Host, c.Port, c.DB)
		}
		return map[string]string{
			"DATABASE_URL": url, "PGHOST": c.Host, "PGPORT": strconv.Itoa(c.Port),
			"PGUSER": c.User, "PGPASSWORD": c.Pass, "PGDATABASE": c.DB,
		}
	case "mysql":
		url := c.URL
		if url == "" {
			url = fmt.Sprintf("mysql://%s:%s@%s:%d/%s", c.User, c.Pass, c.Host, c.Port, c.DB)
		}
		return map[string]string{
			"DATABASE_URL": url, "MYSQL_HOST": c.Host, "MYSQL_PORT": strconv.Itoa(c.Port),
			"MYSQL_USER": c.User, "MYSQL_PASSWORD": c.Pass, "MYSQL_DATABASE": c.DB,
		}
	case "redis":
		url := c.URL
		if url == "" {
			url = fmt.Sprintf("redis://%s:%d", c.Host, c.Port)
		}
		return map[string]string{"REDIS_URL": url}
	default:
		if c.URL != "" {
			return map[string]string{"DATABASE_URL": c.URL}
		}
		return map[string]string{}
	}
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- backups (Postgres / MySQL) ----

// Backup is one stored dump file.
type Backup struct {
	Name    string
	Size    int64
	ModTime time.Time
}

func (m *Manager) serviceBackupDir(svc *store.Service) string {
	return filepath.Join(m.BackupsDir, safeName(svc.Name))
}

// BackupService dumps a managed database to a timestamped .sql file and
// returns the filename.
func (m *Manager) BackupService(ctx context.Context, serviceID int64) (string, error) {
	svc, err := m.Store.GetService(serviceID)
	if err != nil {
		return "", err
	}
	if svc.Mode != "managed" {
		return "", errors.New("only managed services can be backed up")
	}
	if m.Agent == nil {
		return "", errors.New("agent not configured")
	}
	env, cmd, err := dumpCommand(svc.Engine, m.decodeCreds(svc))
	if err != nil {
		return "", err
	}
	dir := m.serviceBackupDir(svc)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := time.Now().UTC().Format("20060102-150405") + ".sql"
	tmp := filepath.Join(dir, name+".part")
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	spec := agent.ExecSpec{Container: ServiceName(svc.Name), Env: env, Cmd: cmd}
	if err := m.Agent.ExecOut(ctx, spec, f); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	f.Close()
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return "", err
	}
	return name, nil
}

// ListBackups returns a service's dump files, newest first.
func (m *Manager) ListBackups(serviceID int64) ([]Backup, error) {
	svc, err := m.Store.GetService(serviceID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.serviceBackupDir(svc))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Backup
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Backup{Name: e.Name(), Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// BackupPath returns the on-disk path of a named backup (guards traversal).
func (m *Manager) BackupPath(serviceID int64, name string) (string, error) {
	if err := safeBackupName(name); err != nil {
		return "", err
	}
	svc, err := m.Store.GetService(serviceID)
	if err != nil {
		return "", err
	}
	return filepath.Join(m.serviceBackupDir(svc), name), nil
}

// RestoreService pipes a stored dump back into the managed database.
func (m *Manager) RestoreService(ctx context.Context, serviceID int64, name string) error {
	if err := safeBackupName(name); err != nil {
		return err
	}
	svc, err := m.Store.GetService(serviceID)
	if err != nil {
		return err
	}
	if svc.Mode != "managed" {
		return errors.New("only managed services can be restored")
	}
	if m.Agent == nil {
		return errors.New("agent not configured")
	}
	env, cmd, err := restoreCommand(svc.Engine, m.decodeCreds(svc))
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(m.serviceBackupDir(svc), name))
	if err != nil {
		return err
	}
	defer f.Close()
	return m.Agent.ExecIn(ctx, agent.ExecSpec{Container: ServiceName(svc.Name), Env: env, Cmd: cmd}, f)
}

func safeBackupName(name string) error {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || !strings.HasSuffix(name, ".sql") {
		return errors.New("invalid backup name")
	}
	return nil
}

func dumpCommand(engine string, c Creds) (map[string]string, []string, error) {
	switch engine {
	case "postgres":
		return map[string]string{"PGPASSWORD": c.Pass}, []string{"pg_dump", "-U", c.User, c.DB}, nil
	case "mysql":
		return map[string]string{"MYSQL_PWD": c.Pass}, []string{"mysqldump", "-u", c.User, c.DB}, nil
	default:
		return nil, nil, fmt.Errorf("backups aren't supported for %s services", engine)
	}
}

func restoreCommand(engine string, c Creds) (map[string]string, []string, error) {
	switch engine {
	case "postgres":
		return map[string]string{"PGPASSWORD": c.Pass}, []string{"psql", "-U", c.User, c.DB}, nil
	case "mysql":
		return map[string]string{"MYSQL_PWD": c.Pass}, []string{"mysql", "-u", c.User, c.DB}, nil
	default:
		return nil, nil, fmt.Errorf("restore isn't supported for %s services", engine)
	}
}
