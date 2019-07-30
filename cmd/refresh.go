// Package cmd - contains the refresh sub-command
package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mtlang/Policy-Urchin/refresh"
)

// refreshCmd represents the refresh command
var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh local cache of iam resources",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log := GetLogger(viper.GetViper())
		log.Debugf("log level set to '%s'", viper.GetString("log-level"))

		var c *aws.Config
		sess, err := session.NewSession(c)
		if err != nil {
			log.Fatal(err)
		}

		refresh.Refresh(log, sess)

	},
}

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(refreshCmd)

	bindParams := []string{}

	for _, param := range bindParams {
		if err := viper.BindPFlag(
			param, refreshCmd.Flags().Lookup(param)); err != nil {
			panic(fmt.Sprintf("cannot map config param '%s': %s", param, err.Error()))
		}
	}

}
