package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// rawConn is a minimal JSON-RPC v2 client driven directly over an mcp.Connection, bypassing
// mcp.Client and mcp.ClientSession entirely
type rawConn struct {
	conn mcp.Connection
	// status records the last HTTP response status (and any auth challenge
	// header) this connection's transport saw, so a later write/read
	// failure can be classified as a clean 401/403 rejection instead of
	// guessed at from error text. Always non-nil; reads zero/empty for
	// stdio, which has no HTTP response to observe.
	status *responseSniff

	mu       sync.Mutex
	nextID   int64
	pending  map[int64]chan *jsonrpc.Response
	closed   bool
	closeErr error
}

func dialRaw(ctx context.Context, tr mcp.Transport) (*rawConn, error) {
	status := snoopStatus(tr)
	conn, err := tr.Connect(ctx)
	if err != nil {
		return nil, classifyDialErr(err, status.status.Load())
	}
	rc := &rawConn{conn: conn, status: status, pending: map[int64]chan *jsonrpc.Response{}}
	go rc.readLoop()
	return rc, nil
}

// readLoop dispatches responses to whoever is waiting for that ID. Requests
// and notifications sent by the peer are not needed for probing and are
// dropped.
func (rc *rawConn) readLoop() {
	for {
		msg, err := rc.conn.Read(context.Background())
		if err != nil {
			rc.fail(err)
			return
		}
		resp, ok := msg.(*jsonrpc.Response)
		if !ok {
			continue
		}
		id, err := idInt64(resp.ID)
		if err != nil {
			continue
		}
		rc.mu.Lock()
		ch, ok := rc.pending[id]
		if ok {
			delete(rc.pending, id)
		}
		rc.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
}

func (rc *rawConn) fail(err error) {
	rc.mu.Lock()
	if rc.closed {
		rc.mu.Unlock()
		return
	}
	rc.closed = true
	rc.closeErr = err
	pending := rc.pending
	rc.pending = nil
	rc.mu.Unlock()
	for _, ch := range pending {
		close(ch)
	}
}

func (rc *rawConn) close() error {
	rc.fail(errors.New("closed by caller"))
	return rc.conn.Close()
}

// call sends a request and waits for its response or for ctx to end. A
// well-formed JSON-RPC error response comes back as *analyzer.ProtocolError
// so a caller can tell "the server rejected this cleanly" from "the
// connection died".
func (rc *rawConn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	rc.mu.Lock()
	if rc.closed {
		err := rc.closeErr
		rc.mu.Unlock()
		return nil, classifyDialErr(fmt.Errorf("connection closed: %w", err), rc.status.status.Load())
	}
	rc.nextID++
	id := rc.nextID
	ch := make(chan *jsonrpc.Response, 1)
	rc.pending[id] = ch
	rc.mu.Unlock()
	responsesBefore := rc.status.responses.Load()

	raw, err := marshalParams(params)
	if err != nil {
		return nil, err
	}
	// MakeID only accepts the types a decoded JSON id can take, so an int64
	// request id is built as a float64 - the same as if it had round-tripped
	// through JSON
	reqID, err := jsonrpc.MakeID(float64(id))
	if err != nil {
		return nil, err
	}
	req := &jsonrpc.Request{ID: reqID, Method: method, Params: raw}
	if err := rc.conn.Write(ctx, req); err != nil {
		rc.mu.Lock()
		delete(rc.pending, id)
		rc.mu.Unlock()
		return nil, rc.failed(ctx, err, responsesBefore, false)
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			rc.mu.Lock()
			cerr := rc.closeErr
			rc.mu.Unlock()
			return nil, rc.failed(ctx, fmt.Errorf("connection closed while waiting for %s: %w", method, cerr), responsesBefore, true)
		}
		if resp.Error != nil {
			if werr, ok := errors.AsType[*jsonrpc.Error](resp.Error); ok {
				return nil, &analyzer.ProtocolError{Code: werr.Code, Message: werr.Message, Data: werr.Data}
			}
			return nil, resp.Error
		}
		return resp.Result, nil
	case <-ctx.Done():
		rc.mu.Lock()
		delete(rc.pending, id)
		rc.mu.Unlock()
		return nil, ctx.Err()
	}
}

// failed classifies one request without reusing an earlier HTTP status. A request with no answer
// is ErrConnectionClosed unless the caller's context ended first.
func (rc *rawConn) failed(ctx context.Context, err error, responsesBefore int64, readClosed bool) error {
	answered := rc.status.responses.Load() != responsesBefore
	var status int32
	if answered {
		status = rc.status.status.Load()
	}
	if (readClosed || !answered) && ctx.Err() == nil {
		err = fmt.Errorf("%w: %w", analyzer.ErrConnectionClosed, err)
	}
	return classifyDialErr(err, status)
}

func (rc *rawConn) notify(ctx context.Context, method string, params any) error {
	raw, err := marshalParams(params)
	if err != nil {
		return err
	}
	return classifyDialErr(rc.conn.Write(ctx, &jsonrpc.Request{Method: method, Params: raw}), rc.status.status.Load())
}

func marshalParams(params any) (json.RawMessage, error) {
	if params == nil {
		return nil, nil
	}
	if raw, ok := params.(json.RawMessage); ok {
		return raw, nil
	}
	return json.Marshal(params)
}

func idInt64(id jsonrpc.ID) (int64, error) {
	switch v := id.Raw().(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unexpected id type %T", v)
	}
}
