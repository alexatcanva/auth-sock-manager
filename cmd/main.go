package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/alexatcanva/auth-sock-manager/pkg/authsockmanager"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	flagFingerprint = flag.String("fingerprint", "", "SSH PublicKey Fingerprint")
	flagListen      = flag.String("listen", "", "Listen socket path for SSH Agent Connections")
)

func main() {
	fmt.Fprintf(os.Stderr, "Starting auth-sock-manager with args: %#v\n", os.Args)
	flag.Parse()

	if *flagFingerprint == "" {
		panic("fingerprint is required")
	}

	if *flagListen != "" {
		listen(*flagFingerprint, *flagListen)
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		panic("SSH_AUTH_SOCK is not set")
	}

	agentConn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Printf("Failed to connect to SSH Agent: %s\n", err)
		os.Exit(1)
	}
	defer agentConn.Close()

	keys, err := agent.NewClient(agentConn).List()
	if err != nil {
		fmt.Printf("Failed to list SSH Keys: %s\n", err)
		os.Exit(1)
	}
	for _, key := range keys {
		if ssh.FingerprintSHA256(key) == *flagFingerprint {
			fmt.Printf("Found SSH Key: %s\n", key)
		}
	}

	f, err := os.CreateTemp(os.TempDir(), "auth-sock-manager-*.sock")
	if err != nil {
		panic(err)
	}
	socketName := f.Name()
	err = f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to close temp file: %s", err)
	}
	os.Remove(socketName)

	pid, err := syscall.ForkExec(
		"/Users/alexb/dev/auth-sock-manager/auth-sock-manager",
		[]string{
			"/Users/alexb/dev/auth-sock-manager/auth-sock-manager",
			fmt.Sprintf("-fingerprint=%s", *flagFingerprint),
			fmt.Sprintf("-listen=%s", socketName),
		},
		&syscall.ProcAttr{
			Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
			Sys: &syscall.SysProcAttr{
				Setsid: true,
			},
			Env: []string{
				fmt.Sprintf("SSH_AUTH_SOCK=%s", sock),
			},
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to start agent manager: %s", err)
	}

	fmt.Fprintf(os.Stderr, "Started agent manager with PID: %d\n", pid)
	fmt.Fprintf(os.Stdout, "%s", socketName)
}

func listen(fingerprint, socketName string) {
	l, err := net.Listen("unix", socketName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to start auth-agent-manager listener: %s", err)
	}
	defer l.Close()
	defer os.Remove(socketName)

	agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		fmt.Printf("Failed to connect to SSH Agent: %s\n", err)
		return
	}
	defer agentConn.Close()

	realAgent := agent.NewClient(agentConn)
	limited := authsockmanager.NewLimitedAgent(realAgent, []string{fingerprint})

	fmt.Printf("Listening for SSH Agent Connections on %s\n", socketName)
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to accept connection: %s", err)
		}
		go agent.ServeAgent(limited, conn)
	}
}
