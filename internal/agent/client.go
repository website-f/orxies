package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Client is the control plane's handle to the agent. It dials the
// agent's unix socket and authenticates with the shared secret.
type Client struct {
	http   *http.Client
	base   string
	secret string
}

// NewClient dials the agent over the unix socket at socketPath.
func NewClient(socketPath, secret string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{http: &http.Client{Transport: tr}, base: "http://unix", secret: secret}
}

// newClientRaw points a client at an arbitrary base URL (tests).
func newClientRaw(hc *http.Client, base, secret string) *Client {
	return &Client{http: hc, base: base, secret: secret}
}

func (c *Client) newReq(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", c.secret)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := c.newReq(ctx, http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := c.newReq(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Health reports agent/docker/nixpacks readiness.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var h Health
	err := c.getJSON(ctx, "/v1/health", &h)
	return h, err
}

// Build streams the build log to logs and returns an error if the build
// fails. Blocks for the duration of the build.
func (c *Client) Build(ctx context.Context, spec BuildSpec, logs io.Writer) error {
	b, _ := json.Marshal(spec)
	req, err := c.newReq(ctx, http.MethodPost, "/v1/build", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("build: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var failMsg string
	failed := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "orxies-build: FAILED:"):
			failed = true
			failMsg = strings.TrimSpace(strings.TrimPrefix(line, "orxies-build: FAILED:"))
		case strings.HasPrefix(line, "orxies-build: OK"):
			// terminal success marker
		default:
			if logs != nil {
				io.WriteString(logs, line+"\n")
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("build stream: %w", err)
	}
	if failed {
		return fmt.Errorf("build failed: %s", failMsg)
	}
	return nil
}

// Run starts the container and returns its id.
func (c *Client) Run(ctx context.Context, spec RunSpec) (string, error) {
	var out struct {
		ContainerID string `json:"container_id"`
	}
	err := c.postJSON(ctx, "/v1/run", spec, &out)
	return out.ContainerID, err
}

// Stop stops the container by name.
func (c *Client) Stop(ctx context.Context, name string) error {
	return c.postJSON(ctx, "/v1/stop", map[string]string{"name": name}, nil)
}

// EnsureNetwork creates the named docker network if absent.
func (c *Client) EnsureNetwork(ctx context.Context, name string) error {
	return c.postJSON(ctx, "/v1/network", map[string]string{"name": name}, nil)
}

// Remove force-removes the container by name.
func (c *Client) Remove(ctx context.Context, name string) error {
	return c.postJSON(ctx, "/v1/remove", map[string]string{"name": name}, nil)
}

// Status returns the container's state.
func (c *Client) Status(ctx context.Context, name string) (Status, error) {
	var st Status
	err := c.getJSON(ctx, "/v1/status?name="+url.QueryEscape(name), &st)
	return st, err
}

// Logs copies up to `tail` lines of the container's logs to w.
func (c *Client) Logs(ctx context.Context, name string, tail int, w io.Writer) error {
	req, err := c.newReq(ctx, http.MethodGet, "/v1/logs?name="+url.QueryEscape(name)+"&tail="+strconv.Itoa(tail), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logs: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	_, err = io.Copy(w, resp.Body)
	return err
}
