// Package cmd - contains the version sub-command
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// GitCommit - The git commit that was compiled. This will be filled in by the compiler.
var GitCommit string

// Unit - this application's name
var Unit string

// Version - The main version number that is being run at the moment.
var Version string

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version info and exit",
	Long: `Print the version of this command and git commit hash
if the current build is dirty.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(versionInfo())
		os.Exit(0)
	},
}

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(versionCmd)
}

// versionInfo - vendoring version info
func versionInfo() string {
	Unit = "policy-urchin"
	Version = "1.0"
	return fmt.Sprintf("%s v%s (%s)", Unit, Version, GitCommit)
}
