// Package cmd - contains the version sub-command
package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mtlang/Policy-Urchin/users"
)

// versionCmd represents the version command
var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Analyze all users in account for usage",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log := GetLogger(viper.GetViper())
		log.Debugf("log level set to '%s'", viper.GetString("log-level"))

		var c *aws.Config
		sess, err := session.NewSession(c)
		if err != nil {
			log.Fatal(err)
		}

		users.Users(log, sess)

	},
}

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(usersCmd)
	usersCmd.Flags().StringP("end-time", "E", "", "Unix time (in seconds) of latest time to search for activity")
	usersCmd.Flags().IntP("events", "e", 50, "Minimum number of events to examine")
	usersCmd.Flags().StringP("region", "r", "us-east-1", "Region to search for activity in (use \"all\" to search all regions)")
	usersCmd.Flags().StringP("start-time", "s", "", "Unix time (in seconds) of soonest time to search for activity")
	usersCmd.Flags().StringP("user", "u", "", "Name of a single user to analyze")

	bindParams := []string{
		"end-time",
		"events",
		"region",
		"start-time",
		"user",
	}

	for _, param := range bindParams {
		if err := viper.BindPFlag(
			param, usersCmd.Flags().Lookup(param)); err != nil {
			panic(fmt.Sprintf("cannot map config param '%s': %s", param, err.Error()))
		}
	}

}
