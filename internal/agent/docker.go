package agent

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// CLIRunner is the production Runner. It shells out to the `docker` and
// `nixpacks` binaries present in the agent image. Shelling out (rather
// than linking the Docker SDK) keeps the Go dependency surface tiny.
type CLIRunner struct{}

var _ Runner = CLIRunner{}

func (CLIRunner) Build(ctx context.Context, spec BuildSpec, logs io.Writer) error {
	var cmd *exec.Cmd
	switch spec.Strategy {
	case "dockerfile":
		args := []string{"build", "-t", spec.Name}
		if spec.Dockerfile != "" {
			args = append(args, "-f", filepath.Join(spec.SourcePath, spec.Dockerfile))
		}
		args = append(args, spec.SourcePath)
		cmd = exec.CommandContext(ctx, "docker", args...)
	case "nixpacks":
		cmd = exec.CommandContext(ctx, "nixpacks", "build", spec.SourcePath, "--name", spec.Name)
	default:
		return fmt.Errorf("unknown build strategy %q", spec.Strategy)
	}
	cmd.Stdout = logs
	cmd.Stderr = logs
	return cmd.Run()
}

func (CLIRunner) Run(ctx context.Context, spec RunSpec) (string, error) {
	args := []string{"run", "-d", "--name", spec.Name, "--restart", "unless-stopped"}
	if spec.HostPort > 0 { // publish to host loopback (app containers); services skip this
		args = append(args, "-p", fmt.Sprintf("127.0.0.1:%d:%d", spec.HostPort, spec.AppPort))
	}
	if spec.Network != "" {
		args = append(args, "--network", spec.Network)
	}
	if !spec.Unhardened { // DB images need setuid/chown on first boot, so they opt out
		args = append(args, "--security-opt", "no-new-privileges", "--cap-drop", "ALL")
	}
	if spec.MemoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", spec.MemoryMB))
	}
	for vol, path := range spec.Volumes {
		args = append(args, "-v", vol+":"+path)
	}
	for k, v := range spec.Env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, spec.Image)
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// EnsureNetwork creates a docker network if it doesn't already exist.
func (CLIRunner) EnsureNetwork(ctx context.Context, name string) error {
	// `docker network inspect` succeeds if it exists; only create otherwise.
	if err := exec.CommandContext(ctx, "docker", "network", "inspect", name).Run(); err == nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, "docker", "network", "create", name).CombinedOutput()
	if err != nil {
		// Tolerate a race where a concurrent create won.
		if strings.Contains(string(out), "already exists") {
			return nil
		}
		return fmt.Errorf("docker network create: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (CLIRunner) Stop(ctx context.Context, name string) error {
	return dockerCmd(ctx, "stop", name)
}

func (CLIRunner) Remove(ctx context.Context, name string) error {
	return dockerCmd(ctx, "rm", "-f", name)
}

func (CLIRunner) Logs(ctx context.Context, name string, tail int, w io.Writer) error {
	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", strconv.Itoa(tail), name)
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

func (CLIRunner) Status(ctx context.Context, name string) (Status, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Status}}", name).CombinedOutput()
	if err != nil {
		// `docker inspect` errors when the container doesn't exist — treat
		// as "absent", not a hard failure.
		return Status{State: "", Running: false}, nil
	}
	st := strings.TrimSpace(string(out))
	return Status{State: st, Running: st == "running"}, nil
}

func (CLIRunner) Health(ctx context.Context) Health {
	h := Health{}
	if err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Run(); err == nil {
		h.Docker = true
	}
	if _, err := exec.LookPath("nixpacks"); err == nil {
		h.Nixpacks = true
	}
	h.OK = h.Docker
	if !h.Docker {
		h.Detail = "docker daemon unreachable"
	}
	return h
}

func dockerCmd(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
