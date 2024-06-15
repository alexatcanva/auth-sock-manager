/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/alexatcanva/auth-sock-manager/pkg/authsockmanager"
	"github.com/spf13/cobra"
)

// listenCmd represents the listen command
var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen on a socket for SSH Agent connections.",
	Long: `Listen on a unix socket for SSH agent connections. 
This agent will only provide the given keys specified by the --fingerprint flag.`,
	Run: runListen,
}

func init() {
	listenCmd.Flags().StringSlice("fingerprints", []string{}, "SSH Public Key Fingerprint")
	listenCmd.MarkFlagRequired("fingerprints")
	listenCmd.Flags().String("socket", "", "The linux domain socket to listen on.")
	listenCmd.MarkFlagRequired("socket")
	rootCmd.AddCommand(listenCmd)
}

func runListen(cmd *cobra.Command, args []string) {
	fingerprints, _ := cmd.Flags().GetStringSlice("fingerprints")
	socketName, _ := cmd.Flags().GetString("socket")
	fmt.Printf("Listening for SSH Agent Connections on %s\n", socketName)

	real, _, err := authsockmanager.RealSshAgent()
	if err != nil {
		fmt.Printf("Failed to connect to real SSH Agent: %s\n", err)
		os.Exit(1)
	}

	limited, err := authsockmanager.NewLimitedAgent(real, fingerprints)
	if err != nil {
		fmt.Printf("Failed to create Limited Agent: %s\n", err)
		os.Exit(1)
	}

	err = authsockmanager.NewAuthSockManagerServer(limited, socketName).Listen()
	if err != nil {
		fmt.Printf("Failed to listen on %s: %s\n", socketName, err)
		os.Exit(1)
	}
}
