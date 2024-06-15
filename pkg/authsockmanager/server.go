package authsockmanager

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// AuthSockManagerServer is a server that manages the SSH Agent socket.
type AuthSockManagerServer struct {
	// mu protects the following fields:
	// timer
	mu sync.Mutex

	// timer keeps track of the time to wait before closing the socket
	// we give a 5 minute grace period since the last time we were queried
	// for a key.
	// If the server exceeds this 5 minute grace period, we close the socket
	// and clean up our resources.
	timer *time.Timer

	agent      agent.Agent
	unixSocket string
}

// NewAuthSockManagerServer creates a new AuthSockManagerServer.
func NewAuthSockManagerServer(
	agent agent.Agent,
	unixSocket string,
) *AuthSockManagerServer {
	return &AuthSockManagerServer{
		agent:      agent,
		unixSocket: unixSocket,
	}
}

// Listen starts the AuthSockManagerServer.
func (a *AuthSockManagerServer) Listen() error {
	// start timer
	a.timer = time.NewTimer(5 * time.Minute)

	l, err := net.Listen("unix", a.unixSocket)
	if err != nil {
		return fmt.Errorf("unable to start auth-agent-manager listener: %w", err)
	}
	defer func() {
		l.Close()
		os.Remove(a.unixSocket)
	}()

	for {
		select {
		// if we have exceeded our grace period, close the socket and clean up
		// our resources
		case <-a.timer.C:
			return nil
		// otherwise, accept a new connection and serve the agent
		default:
			conn, err := l.Accept()
			if err != nil {
				// continue here on bad connections
				continue
			}
			go a.ServeAgent(conn)
		}
	}
}

func (a *AuthSockManagerServer) ServeAgent(conn net.Conn) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.timer.Reset(5 * time.Minute)
	go agent.ServeAgent(a.agent, conn)
	return nil
}
