package authsockmanager

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type LimitedAgent struct {
	agent               agent.Agent
	allowedFingerprints []string
}

func NewLimitedAgent(agent agent.Agent, allowedFingerprints []string) *LimitedAgent {
	return &LimitedAgent{
		agent:               agent,
		allowedFingerprints: allowedFingerprints,
	}
}

// Add implements agent.Agent.
func (l *LimitedAgent) Add(key agent.AddedKey) error {
	return l.agent.Add(key)
}

// List implements agent.Agent.
func (l *LimitedAgent) List() ([]*agent.Key, error) {
	keys, err := l.agent.List()
	if err != nil {
		return nil, err
	}
	if len(l.allowedFingerprints) == 0 {
		return keys, nil
	}
	returnKeys := []*agent.Key{}
	for _, key := range keys {
		if ssh.FingerprintSHA256(key) == l.allowedFingerprints[0] {
			returnKeys = append(returnKeys, key)
		}
	}
	return returnKeys, nil
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
	return l.agent.Signers()
}

// Unlock implements agent.Agent.
func (l *LimitedAgent) Unlock(passphrase []byte) error {
	return l.agent.Unlock(passphrase)
}

var _ agent.Agent = (*LimitedAgent)(nil)
