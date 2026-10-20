package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/runtime/canary"
	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestBuildArgsExact(t *testing.T) {
	got := buildArgs(spec{
		ContainerName: "mcpscan-test1",
		Image:         "mcp-scanner-sandbox-base:latest",
		MountDir:      "/tmp/mcpscan-run-abc",
		WorkDir:       "/work",
		Entrypoint:    "/sandbox/entrypoint",
		Args:          []string{"serve", "--config", "/sandbox/config.json"},
		Env:           map[string]string{"DB_PASSWORD": "canary-db-x", "API_TOKEN": "sk-canary-y", "HOME": canary.ContainerHome},
		Memory:        "256m",
		CPUs:          "1.0",
		PIDsLimit:     64,
		TmpfsSize:     "64m",
	})

	want := []string{
		"create", "--rm", "-i",
		"--name", "mcpscan-test1",
		"--read-only",
		"--user", "65532:65532",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "64",
		"--memory", "256m",
		"--cpus", "1.0",
		"--tmpfs", "/work:rw,noexec,nosuid,size=64m",
		"-w", "/work",
		"-v", "/tmp/mcpscan-run-abc:/sandbox:ro",
		"--network", "none",
		"-e", "API_TOKEN=sk-canary-y",
		"-e", "DB_PASSWORD=canary-db-x",
		// Without HOME the container gets HOME=/ for a numeric user, and
		// every planted file canary sits somewhere the target never looks
		"-e", "HOME=/sandbox/home",
		"mcp-scanner-sandbox-base:latest", "/sandbox/entrypoint",
		"serve", "--config", "/sandbox/config.json",
	}

	if len(got) != len(want) {
		t.Fatalf("argv length mismatch\n got: %#v\nwant: %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q\nfull got: %#v", i, got[i], want[i], got)
		}
	}
}

func TestBuildArgsNeverEscapesTheSandbox(t *testing.T) {
	got := buildArgs(spec{
		ContainerName: "mcpscan-test3",
		Image:         "img", MountDir: "/tmp/x", WorkDir: "/work", Entrypoint: "/sandbox/entrypoint",
		PIDsLimit: 64, Memory: "256m", CPUs: "1.0", TmpfsSize: "64m",
	})
	joined := strings.Join(got, " ")
	forSubstring := []string{"docker.sock", "/home", os.Getenv("HOME")}
	for _, f := range forSubstring {
		if f == "" {
			continue
		}
		if strings.Contains(joined, f) {
			t.Fatalf("argv contains forbidden token %q: %v", f, got)
		}
	}

	forExact := map[string]bool{"--privileged": true, "--pid": true, "--cap-add": true}
	for _, a := range got {
		if forExact[a] {
			t.Fatalf("argv contains forbidden flag %q: %v", a, got)
		}
	}
	mustContain := []string{"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532"}
	for _, m := range mustContain {
		if !strings.Contains(joined, m) {
			t.Fatalf("argv missing required token %q: %v", m, got)
		}
	}
}

func TestBuildArgsMountIsAlwaysUnderGivenTempDir(t *testing.T) {
	tmp := t.TempDir()
	got := buildArgs(spec{
		ContainerName: "mcpscan-test4",
		Image:         "img", MountDir: tmp, WorkDir: "/work", Entrypoint: "/sandbox/entrypoint",
		PIDsLimit: 64, Memory: "256m", CPUs: "1.0", TmpfsSize: "64m",
	})
	found := false
	for i, a := range got {
		if a == "-v" && i+1 < len(got) {
			mount := got[i+1]
			if !strings.HasPrefix(mount, tmp+":") {
				t.Fatalf("bind mount %q does not come from the given temp dir %q", mount, tmp)
			}
			if !strings.HasSuffix(mount, ":ro") {
				t.Fatalf("bind mount %q is not read-only", mount)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no bind mount found in argv: %v", got)
	}
}

// fixtureDeadline gives normal fixture runs enough time on a loaded host. Timeout tests use
// their own shorter deadline.
const fixtureDeadline = 60 * time.Second

func requireDocker(t *testing.T) *Docker {
	t.Helper()
	d := New()
	if err := d.Available(context.Background()); err != nil {
		t.Skipf("docker not available, skipping: %v", err)
	}
	return d
}

// buildFixture compiles a testdata/runtime fixture into a fresh temp file
// and returns its absolute path
func buildFixture(t *testing.T, pkg string) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "fixture")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/runtime/"+pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fixture %s: %v\n%s", pkg, err, out)
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/runtime/sandbox -> repo root
	return filepath.Join(wd, "..", "..", "..")
}

func TestExecuteRunsBenignFixture(t *testing.T) {
	d := requireDocker(t)
	bin := buildFixture(t, "benign")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: fixtureDeadline,
	})
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}
	if !res.Started {
		t.Fatalf("expected Started=true")
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr=%s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hello from sandbox") {
		t.Fatalf("stdout missing expected output: %q", res.Stdout)
	}
	if !res.Hit("process_exec") {
		t.Fatalf("expected a process_exec observation, got %+v", res.Observations)
	}
}

func TestExecuteRejectsRelativeCommand(t *testing.T) {
	d := New() // no docker needed, fails validation before touching it
	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target: model.Target{Kind: model.TargetStdio, Command: "relative/path"},
	})
	if res.Err == nil {
		t.Fatalf("expected an error for a relative command path")
	}
}

func TestExecuteRejectsNonStdioTarget(t *testing.T) {
	d := New()
	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target: model.Target{Kind: model.TargetRemote, URL: "https://example.invalid"},
	})
	if res.Err == nil {
		t.Fatalf("expected an error for a non-stdio target")
	}
}

func TestExecuteMissingImageFailsRatherThanSucceeding(t *testing.T) {
	d := requireDocker(t)
	d.Image = "Mcpscan-Test-INVALID-Image-Name"
	bin := buildFixture(t, "benign")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: fixtureDeadline,
	})
	if res.Err == nil {
		t.Fatalf("expected an error when the sandbox image is unusable, got a successful-looking result: %+v", res)
	}
	if res.Started {
		t.Fatalf("an unusable image must never be reported as Started=true")
	}
}

func TestExecuteDynamicallyLinkedEntrypointFailsRatherThanSucceeding(t *testing.T) {
	d := requireDocker(t)
	bin := testutil.DynamicSystemBinary(t)

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: fixtureDeadline,
	})
	if res.Err == nil {
		t.Fatalf("expected an error when the entrypoint needs a dynamic loader the scratch image does not have, got a successful-looking result: %+v", res)
	}
	if res.Started {
		t.Fatalf("an entrypoint that never actually ran must never be reported as Started=true")
	}
}

// A noexec staging mount makes runc refuse the entrypoint, which is a sandbox error rather than
// a started target run
func TestExecuteOnNoexecStagingFailsRatherThanStarting(t *testing.T) {
	d := requireDocker(t)
	d.BaseTempDir = noexecDir(t)
	bin := buildFixture(t, "benign")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: fixtureDeadline,
	})
	if res.Err == nil || res.Started {
		t.Fatalf("an entrypoint runc refused to exec must be an error, not a started run: %+v", res)
	}
}

// noexecDir returns a world-writable directory where a script cannot be executed, or skips
func noexecDir(t *testing.T) string {
	t.Helper()
	for _, dir := range []string{"/run/lock", "/dev/shm"} {
		f, err := os.CreateTemp(dir, "mcpscan-probe-*")
		if err != nil {
			continue
		}
		f.WriteString("#!/bin/sh\n")
		f.Close()
		os.Chmod(f.Name(), 0o755)
		err = exec.Command(f.Name()).Run()
		os.Remove(f.Name())
		if errors.Is(err, os.ErrPermission) {
			return dir
		}
	}
	t.Skip("no writable noexec mount on this host")
	return ""
}

func TestExecuteCleansUpContainerOnTimeout(t *testing.T) {
	d := requireDocker(t)
	d.nameTag = randSuffix() + "-"
	bin := buildFixture(t, "sleeper")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: 2 * time.Second,
	})
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true")
	}

	// No container from this run should still exist afterward
	requireNoLeftoverContainers(t, "timeout", d)
}

func TestExecuteCleansUpContainerOnCancellation(t *testing.T) {
	d := requireDocker(t)
	d.nameTag = randSuffix() + "-"
	bin := buildFixture(t, "sleeper")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan analyzer.RuntimeResult, 1)
	go func() {
		done <- d.Execute(ctx, analyzer.RuntimeRequest{
			Target:  model.Target{Kind: model.TargetStdio, Command: bin},
			Timeout: 60 * time.Second,
		})
	}()

	// Cancel once the target runs. A fixed delay could land during docker create on a loaded
	// host, which is the path the next test covers and which fails with an error by design.
	waitRunning(t, d)
	cancel()
	res := <-done
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}

	requireNoLeftoverContainers(t, "cancellation", d)
}

// waitRunning blocks until a container carrying d.nameTag is running
func waitRunning(t *testing.T, d *Docker) {
	t.Helper()
	deadline := time.Now().Add(fixtureDeadline)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "ps", "--filter", "name=mcpscan-"+d.nameTag, "--filter", "status=running", "-q").Output()
		if err != nil {
			t.Fatalf("docker ps: %v", err)
		}
		if len(strings.TrimSpace(string(out))) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the sandbox container never reached the running state")
}

// Cancellation during container creation must not leave a container behind
func TestExecuteCancelledDuringCreateLeavesNoContainer(t *testing.T) {
	d := requireDocker(t)
	d.nameTag = randSuffix() + "-"
	bin := buildFixture(t, "sleeper")

	for _, delay := range []time.Duration{0, 10, 25, 50, 100, 200, 400} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(delay*time.Millisecond, cancel)
		d.Execute(ctx, analyzer.RuntimeRequest{
			Target:  model.Target{Kind: model.TargetStdio, Command: bin},
			Timeout: fixtureDeadline,
		})
		cancel()
	}
	// Allow a delayed daemon-side create to become visible before checking cleanup
	time.Sleep(3 * time.Second)
	requireNoLeftoverContainers(t, "cancellation during create", d)
}

func TestExecuteContainsHostileTarget(t *testing.T) {
	d := requireDocker(t)
	bin := buildFixture(t, "malicious")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: fixtureDeadline,
	})
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}

	combined := res.Stdout + res.Stderr
	if strings.Contains(combined, "root:") {
		t.Fatalf("real /etc/passwd content leaked into sandbox output: %q", combined)
	}
	for line := range strings.SplitSeq(combined, "\n") {
		if strings.Contains(line, "net_connect") && strings.Contains(line, "succeeded") {
			t.Fatalf("sandbox reached a real network target: %q", line)
		}
	}
	if !res.Hit("canary_hit") {
		t.Fatalf("expected canary_hit when the hostile target read planted bait, got %+v", res.Observations)
	}
}

func TestExecuteToolCallConfirmsPathTraversal(t *testing.T) {
	d := requireDocker(t)
	bin := buildFixture(t, "pathtraversal")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:    model.Target{Kind: model.TargetStdio, Command: bin},
		Tool:      "read_file",
		Arguments: map[string]any{"path": "../.aws/credentials"},
		Timeout:   fixtureDeadline,
		Canaries: []analyzer.Canary{
			{ID: "aws-1", Path: ".aws/credentials", Value: "AKIACANARYTESTSECRET", Kind: "aws_key"},
			{ID: "notice-1", Path: "public/notice.txt", Value: "safe notice content"},
		},
	})
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}
	if !res.Hit("canary_hit") {
		t.Fatalf("expected canary_hit confirming the traversal, got stdout=%q observations=%+v", res.Stdout, res.Observations)
	}
}

func TestExecuteToolCallConfirmsCommandInjection(t *testing.T) {
	d := requireDocker(t)
	bin := buildFixture(t, "cmdinjection")

	marker := "MCP-CANARY-TEST-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:    model.Target{Kind: model.TargetStdio, Command: bin},
		Tool:      "run_report",
		Arguments: map[string]any{"name": "; echo " + marker + " #"},
		Timeout:   fixtureDeadline,
	})
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}
	found := false
	for _, o := range res.Observations {
		if o.Kind == "process_exec" && strings.Contains(o.Detail, marker) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a process_exec observation carrying the injected marker %q, got %+v (stdout=%q)", marker, res.Observations, res.Stdout)
	}
}

func TestAvailableFailsClearlyWithoutHanging(t *testing.T) {
	d := New()
	d.Image = "irrelevant" // skip base-image build path
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	t.Setenv("PATH", "/nonexistent")

	start := time.Now()
	err := d.Available(ctx)
	if err == nil {
		t.Fatalf("expected an error when docker is not on PATH")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("Available took too long to fail: %v", time.Since(start))
	}
}

// requireNoLeftoverContainers checks only containers tagged by this test
func requireNoLeftoverContainers(t *testing.T, when string, d *Docker) {
	t.Helper()
	if d.nameTag == "" {
		t.Fatal("set d.nameTag before running, or every sandbox container on the host is checked")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := exec.Command("docker", "ps", "-a", "--filter", "name=mcpscan-"+d.nameTag, "--format", "{{.Names}}").Output()
		if err != nil {
			t.Fatalf("docker ps: %v", err)
		}
		leaked := strings.Fields(string(out))
		if len(leaked) == 0 {
			return
		}
		if time.Now().After(deadline) {
			sort.Strings(leaked)
			t.Fatalf("leftover sandbox container(s) after %s: %s", when, strings.Join(leaked, ", "))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestExecuteMemoryKillReportsStartedWithSignalExit(t *testing.T) {
	d := requireDocker(t)
	bin := buildFixture(t, "memoryhog")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: 60 * time.Second,
	})
	if res.Err != nil {
		t.Fatalf("a cgroup kill is the target's behaviour, not a sandbox failure: %v", res.Err)
	}
	if !res.Started || res.TimedOut {
		t.Fatalf("expected Started=true, TimedOut=false for a memory kill, got %+v", res)
	}
	if res.ExitCode != 137 {
		t.Fatalf("expected exit 137 (128 + SIGKILL) from the memory limit, got %d, stdout=%q stderr=%q",
			res.ExitCode, res.Stdout, res.Stderr)
	}
}

// Inspect the container itself for leaked host environment variables or mounts
func TestExecuteHandsTheContainerNothingFromTheHost(t *testing.T) {
	d := requireDocker(t)
	const secret = "host-secret-value-5f3a9c"
	t.Setenv("MCPSCAN_TEST_HOST_SECRET", secret)
	bin := buildFixture(t, "envdump")

	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target:  model.Target{Kind: model.TargetStdio, Command: bin},
		Timeout: fixtureDeadline,
	})
	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}
	if strings.Contains(res.Stdout, secret) {
		t.Fatal("a host environment variable reached the container")
	}

	// Docker provides these mounts; any other host path came from the run arguments
	allowed := map[string]bool{"/": true, "/work": true, "/etc/hosts": true, "/etc/hostname": true, "/etc/resolv.conf": true}
	sawSandbox := false
	for line := range strings.SplitSeq(res.Stdout, "\n") {
		f := strings.Fields(strings.TrimPrefix(line, "MOUNT "))
		if !strings.HasPrefix(line, "MOUNT ") || len(f) < 2 {
			continue
		}
		point, opts := f[0], f[1]
		switch {
		case point == "/sandbox":
			sawSandbox = true
			if !strings.HasPrefix(opts, "ro") {
				t.Errorf("/sandbox is mounted %s, want read-only", opts)
			}
		case allowed[point], strings.HasPrefix(point, "/proc"), strings.HasPrefix(point, "/dev"), strings.HasPrefix(point, "/sys"):
		default:
			t.Errorf("unexpected mount in the container: %s (%s)", point, opts)
		}
	}
	if !sawSandbox {
		t.Fatalf("no mount table in the output: %q", res.Stdout)
	}
}

// DefaultTimeout bounds runs that do not set a request timeout
func TestExecuteWithoutARequestTimeoutUsesTheDefault(t *testing.T) {
	d := requireDocker(t)

	d.DefaultTimeout = 2 * time.Second
	start := time.Now()
	res := d.Execute(context.Background(), analyzer.RuntimeRequest{
		Target: model.Target{Kind: model.TargetStdio, Command: buildFixture(t, "sleeper")},
	})
	if !res.TimedOut {
		t.Fatalf("a target that never exits was not stopped by DefaultTimeout: %+v", res)
	}
	// Allow startup overhead but fail well before the 30-second fallback
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("stopping took %s, want it near the %s default", took, d.DefaultTimeout)
	}

	benign := requireDocker(t)
	res = benign.Execute(context.Background(), analyzer.RuntimeRequest{
		Target: model.Target{Kind: model.TargetStdio, Command: buildFixture(t, "benign")},
	})
	if res.Err != nil || res.TimedOut {
		t.Fatalf("with the default timeout a short run did not finish: timedOut=%v err=%v", res.TimedOut, res.Err)
	}
}
