/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/alexatcanva/auth-sock-manager/pkg/authsockmanager"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// lsCmd represents the ls command
var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the available SSH Keys in your SSH agent.",
	Long:  `A like for like of ssh-add -l`,
	Run:   runList,
}

func init() {
	rootCmd.AddCommand(lsCmd)
}

func runList(cmd *cobra.Command, args []string) {
	agent, _, err := authsockmanager.RealSshAgent()
	if err != nil {
		fmt.Printf("Failed to connect to real SSH Agent: %s\n", err)
		os.Exit(1)
	}

	keys, err := agent.List()
	if err != nil {
		fmt.Printf("Failed to list SSH Keys: %s\n", err)
		os.Exit(1)
	}
	for _, key := range keys {
		fmt.Printf("%s %s %s \n", key.Format, ssh.FingerprintSHA256(key), key.Comment)
	}
}
