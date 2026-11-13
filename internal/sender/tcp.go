package sender

import (
	"context"
	"net"
)

// TCPProbe opens and closes an ordinary TCP connection without application data.
func TCPProbe(ctx context.Context, addr string) ConnectionObservation {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
	if err != nil {
		return ConnectionObservation{Stage: "tcp", Error: err.Error()}
	}
	if err := conn.Close(); err != nil {
		return ConnectionObservation{Stage: "complete", Error: err.Error()}
	}
	return ConnectionObservation{Stage: "complete"}
}
