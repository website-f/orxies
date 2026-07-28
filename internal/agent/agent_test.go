package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeRunner struct {
	buildErr error
	runID    string
	stopped  []string
	status   Status
}

func (f *fakeRunner) Build(_ context.Context, _ BuildSpec, logs io.Writer) error {
	io.WriteString(logs, "step 1\nstep 2\n")
	return f.buildErr
}
func (f *fakeRunner) Run(_ context.Context, _ RunSpec) (string, error) { return f.runID, nil }
func (f *fakeRunner) Stop(_ context.Context, name string) error {
	f.stopped = append(f.stopped, name)
	return nil
}
func (f *fakeRunner) Remove(_ context.Context, _ string) error { return nil }
func (f *fakeRunner) Logs(_ context.Context, _ string, _ int, w io.Writer) error {
	io.WriteString(w, "log line\n")
	return nil
}
func (f *fakeRunner) Status(_ context.Context, _ string) (Status, error) { return f.status, nil }
func (f *fakeRunner) EnsureNetwork(_ context.Context, _ string) error { return nil }
func (f *fakeRunner) ExecOut(_ context.Context, _ ExecSpec, w io.Writer) error {
	io.WriteString(w, "FAKE DUMP\n")
	return nil
}
func (f *fakeRunner) ExecIn(_ context.Context, _ ExecSpec, r io.Reader) error {
	io.Copy(io.Discard, r)
	return nil
}
func (f *fakeRunner) Health(_ context.Context) Health { return Health{OK: true, Docker: true} }

const testSecret = "s3cr3t"

func testClientServer(t *testing.T, r Runner, clientSecret string) *Client {
	t.Helper()
	srv := httptest.NewServer(NewServer(r, []byte(testSecret)).Handler())
	t.Cleanup(srv.Close)
	return newClientRaw(srv.Client(), srv.URL, clientSecret)
}

func TestAgentRejectsWrongSecret(t *testing.T) {
	c := testClientServer(t, &fakeRunner{}, "WRONG")
	if _, err := c.Health(context.Background()); err == nil {
		t.Error("expected auth failure with wrong secret")
	}
}

func TestAgentRoundTrip(t *testing.T) {
	fr := &fakeRunner{runID: "cid123", status: Status{State: "running", Running: true}}
	c := testClientServer(t, fr, testSecret)
	ctx := context.Background()

	if h, err := c.Health(ctx); err != nil || !h.OK {
		t.Fatalf("health: %v %+v", err, h)
	}

	var log bytes.Buffer
	if err := c.Build(ctx, BuildSpec{Name: "img", SourcePath: "/x", Strategy: "dockerfile"}, &log); err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(log.String(), "step 1") {
		t.Errorf("build log missing content: %q", log.String())
	}

	if id, err := c.Run(ctx, RunSpec{Name: "c1", Image: "img", HostPort: 8300, AppPort: 80}); err != nil || id != "cid123" {
		t.Fatalf("run: %v id=%q", err, id)
	}
	if st, err := c.Status(ctx, "c1"); err != nil || !st.Running {
		t.Fatalf("status: %v %+v", err, st)
	}
	if err := c.Stop(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if len(fr.stopped) != 1 || fr.stopped[0] != "c1" {
		t.Errorf("stop not recorded: %v", fr.stopped)
	}
	var logs bytes.Buffer
	if err := c.Logs(ctx, "c1", 50, &logs); err != nil || !strings.Contains(logs.String(), "log line") {
		t.Fatalf("logs: %v %q", err, logs.String())
	}
}

func TestAgentBuildFailurePropagates(t *testing.T) {
	c := testClientServer(t, &fakeRunner{buildErr: errors.New("boom")}, testSecret)
	err := c.Build(context.Background(), BuildSpec{Name: "img", Strategy: "dockerfile"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected build failure carrying 'boom', got %v", err)
	}
}
