// Package sandbox implements analyzer.RuntimeExecutor on top of the Docker CLI. Its container
// flags enforce a read-only root, non-root user, dropped capabilities, bounded resources, and no
// network.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/runtime/canary"
	"github.com/devlab-group/mcp-scanner/internal/runtime/observer"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// nonRootUser is the fixed numeric uid:gid every container runs as. Numeric,
// because the base image has no /etc/passwd entry to look a name up in.
const nonRootUser = "65532:65532"

// sandboxEntrypoint is the fixed container-side path the target binary is
// always bind-mounted at. It is a constant, not derived from anything the
// caller controls, so dockerExecFailureMarker below can anchor on it.
const sandboxEntrypoint = "/sandbox/entrypoint"

// Docker runs targets inside a docker container. The zero value is usable;
// New fills in sane defaults.
type Docker struct {
	// Image is the container base image. It defaults to a locally-built,
	// empty scratch-based image, so a run never needs to pull anything from
	// a registry. Only ever override this with a trusted, minimal image:
	// this executor bind-mounts the entrypoint into it and expects nothing
	// else from the image's own filesystem.
	Image string

	// BaseTempDir is where per-run scanner-owned temp directories are
	// created. Defaults to os.TempDir(). This is the only directory tree
	// ever bind-mounted into a container.
	BaseTempDir string

	Memory    string // docker --memory value, e.g. "256m"
	CPUs      string // docker --cpus value, e.g. "1.0"
	PIDsLimit int64
	TmpfsSize string // size= value for the tmpfs work directory

	DefaultTimeout time.Duration

	// nameTag isolates test container names from concurrent packages; production leaves it empty
	nameTag string

	// Logger receives a warning when a docker cleanup command (removing a
	// container) fails or times out. Defaults to
	// slog.Default() so the failure is never silent even when nothing sets
	// this.
	Logger *slog.Logger

	// buildMu serializes only the base-image build itself, never the
	// presence check: a scan hammering Execute concurrently (the long-lived
	// API server, not the one-scan-per-process CLI) should not queue up
	// behind a lock once the image already exists
	buildMu sync.Mutex
}

func (d *Docker) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// cleanupTimeout bounds a docker cleanup command run from a defer. These run with a fresh
// context rather than the caller's, because the common case is that the caller's context is
// already cancelled or timed out - exactly when cleanup still needs to happen.
const cleanupTimeout = 5 * time.Second

// createTimeout bounds docker create independently of caller cancellation
const createTimeout = 30 * time.Second

// dockerCleanup runs a docker command purely for its side effect (removing a
// container or network) with its own bounded, independent context, and warns
// rather than swallowing the error if it fails or times out
func (d *Docker) dockerCleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			d.logger().Warn("sandbox: docker cleanup timed out", "args", args)
			return
		}
		d.logger().Warn("sandbox: docker cleanup failed", "args", args, "err", err, "output", strings.TrimSpace(string(out)))
	}
}

// New builds a Docker executor with default resource limits
func New() *Docker {
	return &Docker{
		Memory:         "256m",
		CPUs:           "1.0",
		PIDsLimit:      64,
		TmpfsSize:      "64m",
		DefaultTimeout: 30 * time.Second,
	}
}

func (d *Docker) image() string {
	if d.Image != "" {
		return d.Image
	}
	return "mcp-scanner-sandbox-base:latest"
}

func (d *Docker) tempBase() string {
	if d.BaseTempDir != "" {
		return d.BaseTempDir
	}
	return os.TempDir()
}

// Available reports whether the docker CLI is on PATH and its daemon is
// reachable. It always returns within a few seconds rather than hanging: a
// missing or unresponsive daemon must be a clear error, not a stall.
func (d *Docker) Available(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("sandbox: docker CLI not found: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("sandbox: docker daemon did not respond in time")
		}
		msg := strings.TrimSpace(stderr.String())
		return fmt.Errorf("sandbox: docker daemon unavailable: %s", msg)
	}
	return d.ensureImage(ctx)
}

// ensureImage builds the local scratch-based base image if it is not already present. Presence is
// checked per call so a transient daemon or disk failure does not poison a long-lived API process.
func (d *Docker) ensureImage(ctx context.Context) error {
	if d.Image != "" {
		// Caller supplied their own image; not ours to manage
		return nil
	}
	if d.imagePresent(ctx) {
		return nil
	}

	d.buildMu.Lock()
	defer d.buildMu.Unlock()
	// Re-check inside the lock: a concurrent caller may have already built
	// it while this one was waiting
	if d.imagePresent(ctx) {
		return nil
	}

	dir, err := os.MkdirTemp(d.tempBase(), "mcpscan-baseimg-*")
	if err != nil {
		return fmt.Errorf("sandbox: creating build context: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		return fmt.Errorf("sandbox: writing build context: %w", err)
	}
	build := exec.CommandContext(ctx, "docker", "build", "-t", d.image(), dir)
	var stderr bytes.Buffer
	build.Stderr = &stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("sandbox: building base image: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (d *Docker) imagePresent(ctx context.Context) bool {
	inspect := exec.CommandContext(ctx, "docker", "image", "inspect", d.image())
	inspect.Stdout, inspect.Stderr = io.Discard, io.Discard
	return inspect.Run() == nil
}

// spec is the fully-resolved set of inputs to buildArgs. Keeping it separate
// from Docker/RuntimeRequest keeps the argv builder a pure function, which is
// what makes it possible to unit test without a daemon.
type spec struct {
	ContainerName string
	Image         string
	MountDir      string // host path, read-only bind source
	WorkDir       string // container path, tmpfs
	Entrypoint    string // container path, inside MountDir's mount point
	Args          []string
	Env           map[string]string
	Memory        string
	CPUs          string
	PIDsLimit     int64
	TmpfsSize     string
}

// buildArgs is the security boundary. Every flag here is load-bearing; see
// docs/analyzers/runtime-sandbox.md for what each one defends against. This
// function may read only environment variables and paths supplied explicitly in
// spec.
func buildArgs(s spec) []string {
	args := []string{
		"create", "--rm", "-i",
		"--name", s.ContainerName,
		"--read-only",
		"--user", nonRootUser,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", strconv.FormatInt(s.PIDsLimit, 10),
		"--memory", s.Memory,
		"--cpus", s.CPUs,
		"--tmpfs", s.WorkDir + ":rw,noexec,nosuid,size=" + s.TmpfsSize,
		"-w", s.WorkDir,
		"-v", s.MountDir + ":/sandbox:ro",
		"--network", "none",
	}

	envKeys := slices.Sorted(maps.Keys(s.Env))
	for _, k := range envKeys {
		args = append(args, "-e", k+"="+s.Env[k])
	}

	args = append(args, s.Image, s.Entrypoint)
	args = append(args, s.Args...)
	return args
}

// dockerRunFailureExitCodes historically identify Docker failures. With docker start they may
// come from the target, but treating them as failures keeps ambiguous runs from passing.
var dockerRunFailureExitCodes = map[int]string{
	125: "the docker CLI or daemon rejected the run (for example, the sandbox base image is missing)",
	126: "the container's entrypoint exists but could not be invoked",
	127: "the container's entrypoint could not be found",
}

// dockerExecFailureMarker is the exact prefix docker/runc emit when the entrypoint's own
// execve(2) fails before any of the target's own code runs - observed for a dynamically
// linked binary staged into the empty scratch image, whose missing ELF interpreter makes
// execve return ENOENT and docker report a plain nonzero exit (255) instead of a code
// above
const dockerExecFailureMarker = "exec " + sandboxEntrypoint + ":"

// dockerDaemonErrorMarker identifies docker start failures before the container process runs,
// including runc refusing an entrypoint staged on a noexec mount
const dockerDaemonErrorMarker = "Error response from daemon:"

// dockerRunFailed reports whether Docker appears not to have reached the target. The stderr
// markers can be forged by the target, but a false match only fails the scan closed.
func dockerRunFailed(exitCode int, stderr string) (string, bool) {
	if reason, ok := dockerRunFailureExitCodes[exitCode]; ok {
		return reason, true
	}
	if strings.Contains(stderr, dockerExecFailureMarker) || strings.Contains(stderr, dockerDaemonErrorMarker) {
		return "the container runtime could not execute the entrypoint: " + strings.TrimSpace(stderr), true
	}
	return "", false
}

// Execute runs one target inside the sandbox. It never mounts anything
// outside the temp directory it creates for this call, and that directory is
// always removed before Execute returns.
func (d *Docker) Execute(ctx context.Context, req analyzer.RuntimeRequest) analyzer.RuntimeResult {
	res := analyzer.RuntimeResult{}

	if req.Target.Kind != model.TargetStdio {
		res.Err = fmt.Errorf("sandbox: only stdio targets can be sandboxed, got %q", req.Target.Kind)
		return res
	}
	if req.Target.Command == "" {
		res.Err = errors.New("sandbox: target has no command to run")
		return res
	}
	if !filepath.IsAbs(req.Target.Command) {
		res.Err = fmt.Errorf("sandbox: target command must be an absolute path, got %q", req.Target.Command)
		return res
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = d.defaultTimeout()
	}

	if err := d.ensureImage(ctx); err != nil {
		res.Err = err
		return res
	}

	tmp, err := os.MkdirTemp(d.tempBase(), "mcpscan-run-*")
	if err != nil {
		res.Err = fmt.Errorf("sandbox: creating run directory: %w", err)
		return res
	}
	defer os.RemoveAll(tmp)
	// MkdirTemp defaults to 0700, which the container's non-root user (not
	// the owner, not in the owning group) could not even traverse. The
	// directory holds nothing but the copied entrypoint and world-readable
	// canary bait, so widening it to traversable/readable is safe.
	if err := os.Chmod(tmp, 0o755); err != nil {
		res.Err = fmt.Errorf("sandbox: preparing run directory: %w", err)
		return res
	}

	entry := filepath.Join(tmp, "entrypoint")
	if err := copyExecutable(req.Target.Command, entry); err != nil {
		res.Err = fmt.Errorf("sandbox: staging target binary: %w", err)
		return res
	}

	cset, err := canary.Generate()
	if err != nil {
		res.Err = fmt.Errorf("sandbox: generating canaries: %w", err)
		return res
	}
	if len(req.Canaries) > 0 {
		// Caller supplied specific canaries (e.g. to target a known
		// vulnerable path); use those instead of generating fresh ones
		cset.Canaries = req.Canaries
		cset.Files = map[string]string{}
		cset.Env = map[string]string{}
		for _, c := range req.Canaries {
			if c.Path != "" {
				// Content carries the file's real shape, such as an AWS credentials INI block or
				// netrc entry, when it differs from Value, the bare secret matched by a hit
				content := c.Content
				if content == "" {
					content = c.Value
				}
				cset.Files[c.Path] = content
			}
			if c.Env != "" {
				cset.Env[c.Env] = c.Value
			}
		}
	}
	homeDir := filepath.Join(tmp, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		res.Err = fmt.Errorf("sandbox: creating fake home: %w", err)
		return res
	}
	if err := cset.Materialize(homeDir); err != nil {
		res.Err = fmt.Errorf("sandbox: planting canaries: %w", err)
		return res
	}

	env := map[string]string{
		// Without this docker gives a numeric user HOME=/, so a target
		// reading ~/.aws/credentials opens /.aws/... and never finds the
		// canary that was planted for it
		"HOME": canary.ContainerHome,
	}
	maps.Copy(env, cset.Env)

	name := "mcpscan-" + d.nameTag + cset.RunID
	args := buildArgs(spec{
		ContainerName: name,
		Image:         d.image(),
		MountDir:      tmp,
		WorkDir:       "/work",
		Entrypoint:    sandboxEntrypoint,
		Args:          req.Target.Args,
		Env:           env,
		Memory:        d.memoryOr(),
		CPUs:          d.cpusOr(),
		PIDsLimit:     d.pidsOr(),
		TmpfsSize:     d.tmpfsOr(),
	})

	// Removing the container is the reliable cleanup path: it force-kills
	// and removes it regardless of why Execute is returning (cancellation,
	// timeout, normal exit), and because every container runs in its own
	// PID namespace (never --pid=host), killing its PID 1 makes the kernel
	// tear down every process inside it, not just the entrypoint
	defer d.dockerCleanup("rm", "-f", name)

	// Create the named container before applying runCtx. Cleanup can then remove it even when
	// execution is cancelled.
	createCtx, cancelCreate := context.WithTimeout(context.Background(), createTimeout)
	createOut, createErr := exec.CommandContext(createCtx, "docker", args...).CombinedOutput()
	cancelCreate()
	if createErr != nil {
		res.Err = fmt.Errorf("sandbox: container could not be created: %w: %s", createErr, strings.TrimSpace(string(createOut)))
		return res
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "docker", "start", "--attach", "--interactive", name)
	// Without this, Wait blocks until every holder of the output pipes has
	// exited rather than until the context kills the CLI, so a run can
	// overrun the deadline by however long that takes. The docker CLI is
	// single-process, so a second is slack, not a wait.
	cmd.WaitDelay = time.Second
	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	var stdin io.WriteCloser
	if req.Tool != "" {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			res.Err = fmt.Errorf("sandbox: opening stdin: %w", err)
			return res
		}
	}

	if err := cmd.Start(); err != nil {
		res.Err = fmt.Errorf("sandbox: starting container: %w", err)
		return res
	}
	res.Started = true

	if stdin != nil {
		go writeToolCall(stdin, req.Tool, req.Arguments)
	}

	waitErr := cmd.Wait()
	res.TimedOut = runCtx.Err() == context.DeadlineExceeded
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	} else if waitErr != nil {
		res.ExitCode = -1
	}
	// The raw, byte-bounded capture, kept for Observe below. The truncated
	// copies are what the report shows; searching those for canary values
	// meant a tool whose ordinary reply exceeds MaxCapture hid every
	// exposure it made, and at --network none that search is the only
	// observation channel there is.
	rawStdout, rawStderr := stdout.String(), stderr.String()
	res.Stdout = observer.Sanitize(rawStdout, observer.MaxCapture)
	res.Stderr = observer.Sanitize(rawStderr, observer.MaxCapture)
	res.Answered = sawToolCallResponse(rawStdout)

	// A timeout kills the container from outside; its exit code reflects
	// the SIGKILL, not anything docker itself reported about the run, so it
	// is never mistaken for one of the docker-level failures below
	if !res.TimedOut {
		if reason, failed := dockerRunFailed(res.ExitCode, res.Stderr); failed {
			res.Started = false
			res.Err = fmt.Errorf("sandbox: container did not run the entrypoint (exit %d): %s", res.ExitCode, reason)
			return res
		}
	}

	res.Observations = observer.Observe(observer.Input{
		Started:  res.Started,
		ExitCode: res.ExitCode,
		TimedOut: res.TimedOut,
		Reaped:   true, // docker rm -f above always reaps the container's PID namespace
		Stdout:   rawStdout,
		Stderr:   rawStderr,
		Canaries: cset.Canaries,
	})

	return res
}

func (d *Docker) defaultTimeout() time.Duration {
	if d.DefaultTimeout > 0 {
		return d.DefaultTimeout
	}
	return 30 * time.Second
}
func (d *Docker) memoryOr() string {
	if d.Memory != "" {
		return d.Memory
	}
	return "256m"
}
func (d *Docker) cpusOr() string {
	if d.CPUs != "" {
		return d.CPUs
	}
	return "1.0"
}
func (d *Docker) pidsOr() int64 {
	if d.PIDsLimit > 0 {
		return d.PIDsLimit
	}
	return 64
}
func (d *Docker) tmpfsOr() string {
	if d.TmpfsSize != "" {
		return d.TmpfsSize
	}
	return "64m"
}

func randSuffix() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// copyExecutable copies a single file into dst with permissions that are
// readable and executable but never writable, so the sandbox never bind-mounts
// (or even indirectly exposes a writable path to) the original file
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o555)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// toolCallID is the JSON-RPC id writeToolCall gives the tools/call request
const toolCallID = 2

// sawToolCallResponse reports whether stdout contains a result or error for tools/call. An
// initialize reply alone does not prove that the tool ran.
func sawToolCallResponse(stdout string) bool {
	for line := range strings.SplitSeq(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var msg struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg.JSONRPC == "2.0" && string(bytes.TrimSpace(msg.ID)) == strconv.Itoa(toolCallID) {
			return true
		}
	}
	return false
}

// writeToolCall sends a minimal handshake and one tools/call, then closes stdin. Execute records
// whether captured stdout contains a JSON-RPC response; the runtime analyzer decides whether an
// unanswered call makes its result incomplete.
func writeToolCall(w io.WriteCloser, tool string, args map[string]any) {
	defer w.Close()
	writeLine(w, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "mcp-scanner", "version": "1.0"},
		},
	})
	writeLine(w, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	writeLine(w, map[string]any{
		"jsonrpc": "2.0", "id": toolCallID, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
}

func writeLine(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	w.Write(b)
	w.Write([]byte("\n"))
}

// boundedBuffer caps how much output it retains, so a hostile or runaway
// process cannot force unbounded memory growth through stdout/stderr
type boundedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

const boundedBufferLimit = 1 << 20 // 1MiB raw capture, sanitized/truncated further downstream

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() < boundedBufferLimit {
		remaining := min(boundedBufferLimit-b.buf.Len(), len(p))
		b.buf.Write(p[:remaining])
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
