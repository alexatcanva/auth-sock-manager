/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/alexatcanva/auth-sock-manager/pkg/authsockmanager"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "auth-sock-manager",
	Short: "Manage your available SSH Keys within your SSH Agent.",
	Long: `Ever wanted to specify which keys are available to certain SSH sessions?
	
Well fear not, for the auth-sock-manager has you covered! Simply specify the 
fingerprints of the keys you want to make available to a session and the
auth-sock-manager will manage the SSH Agent socket for you!`,
	Run: rootRun,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringSlice("fingerprints", []string{}, "SSH Public Key Fingerprint")
	rootCmd.MarkFlagRequired("fingerprints")
}

func rootRun(cmd *cobra.Command, args []string) {
	_, realSock, err := authsockmanager.RealSshAgent()
	if err != nil {
		fmt.Printf("Failed to connect to SSH Agent: %s\n", err)
		os.Exit(1)
	}

	fingerprints, err := cmd.Flags().GetStringSlice("fingerprints")
	if err != nil {
		fmt.Printf("Failed to get fingerprints: %s\n", err)
		os.Exit(1)
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
		"auth-sock-manager",
		[]string{
			"auth-sock-manager",
			"listen",
			fmt.Sprintf("--fingerprints=%s", strings.Join(fingerprints, ",")),
			fmt.Sprintf("--socket=%s", socketName),
		},
		&syscall.ProcAttr{
			Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
			Sys: &syscall.SysProcAttr{
				Setsid: true,
			},
			Env: []string{
				fmt.Sprintf("SSH_AUTH_SOCK=%s", realSock),
			},
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to start agent manager: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Started agent manager with PID: %d\n", pid)
	fmt.Fprintf(os.Stdout, "%s", socketName)
}
