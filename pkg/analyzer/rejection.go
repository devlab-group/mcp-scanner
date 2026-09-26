package analyzer

import "errors"

// StatusCoder classifies a Dialer or Session error by HTTP status code. Callers must not infer the
// status from error prose.
type StatusCoder interface {
	error
	Status() int
}

// ErrSessionRejected marks a protocol-level rejection of a session id: the target
// affirmatively told the caller the id it presented is not valid (for example the MCP
// "session not found" response to an unrecognized or terminated session), as opposed to the
// connection failing before any answer came back at all. Implementations must wrap it with %w so
// callers can use errors.Is.
var ErrSessionRejected = errors.New("session id rejected by target")

// ErrConnectionClosed marks a request whose peer exited or disconnected before answering. A
// rejection is an answer and must not wrap this error. Implementations must wrap it with %w so
// callers can use errors.Is.
var ErrConnectionClosed = errors.New("connection closed before the request was answered")
