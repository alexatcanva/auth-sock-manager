package authsockmanager

import (
	"fmt"
	"net"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// RealSshAgent returns the SSH Agent on the SSH_AUTH_SOCK env var.
func RealSshAgent() (agent.ExtendedAgent, string, error) {
	sac := os.Getenv("SSH_AUTH_SOCK")
	if sac == "" {
		return nil, sac, fmt.Errorf("SSH_AUTH_SOCK not assigned")
	}
	agentConn, err := net.Dial("unix", sac)
	if err != nil {
		return nil, sac, fmt.Errorf("unable to connect to SSH_AUTH_SOCK: %w", err)
	}

	return agent.NewClient(agentConn), sac, nil
}

type LimitedAgent struct {
	agent               agent.Agent
	allowedFingerprints []string

	signers []ssh.Signer
	keys    []*agent.Key
}

func NewLimitedAgent(agent agent.Agent, allowedFingerprints []string) (*LimitedAgent, error) {
	l := &LimitedAgent{
		agent:               agent,
		allowedFingerprints: allowedFingerprints,
	}
	err := populateLimitedAgent(l)
	if err != nil {
		return nil, fmt.Errorf("unable to populate limited agent: %w", err)
	}
	return l, nil
}

// compile time check to ensure the agent.Agent interface is satisfied.
var _ agent.Agent = (*LimitedAgent)(nil)

func populateLimitedAgent(l *LimitedAgent) error {
	l.signers, l.keys = make([]ssh.Signer, 0), make([]*agent.Key, 0)
	keys, err := l.agent.List()
	if err != nil {
		return fmt.Errorf("unable to get keys from agent %w", err)
	}
	// TODO: add signers
	// _, err := l.agent.Signers()
	// if err != nil {
	// 	return fmt.Errorf("unable to get signers from agent %w", err)
	// }
	for _, key := range keys {
		if slices.Contains(l.allowedFingerprints, ssh.FingerprintSHA256(key)) {
			l.keys = append(l.keys, key)
		}
	}
	// FIXME: remove debug lines
	fmt.Fprintf(os.Stderr, "added keys %v signers: %v\n", l.keys, l.signers)
	return nil
}

// Add implements agent.Agent.
func (l *LimitedAgent) Add(key agent.AddedKey) error {
	return l.agent.Add(key)
}

// List implements agent.Agent.
func (l *LimitedAgent) List() ([]*agent.Key, error) {
	return l.keys, nil
}

// Lock implements agent.Agent.
func (l *LimitedAgent) Lock(passphrase []byte) error {
	return l.agent.Lock(passphrase)
}

// Remove implements agent.Agent.
func (l *LimitedAgent) Remove(key ssh.PublicKey) error {
	return l.agent.Remove(key)
}

// RemoveAll implements agent.Agent.
func (l *LimitedAgent) RemoveAll() error {
	return l.agent.RemoveAll()
}

// Sign implements agent.Agent.
func (l *LimitedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return l.agent.Sign(key, data)
}

// Signers implements agent.Agent.
func (l *LimitedAgent) Signers() ([]ssh.Signer, error) {
	return l.signers, nil
}

// Unlock implements agent.Agent.
func (l *LimitedAgent) Unlock(passphrase []byte) error {
	return l.agent.Unlock(passphrase)
}
