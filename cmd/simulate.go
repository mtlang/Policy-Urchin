package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mtlang/Policy-Urchin/simulate"
)

// sumulateCmd represents the simulate command
var simulateCmd = &cobra.Command{
	Use:   "simulate",
	Short: "See who/what has access to aws resources",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log := GetLogger(viper.GetViper())
		log.Debugf("log level set to '%s'", viper.GetString("log-level"))

		var c *aws.Config
		sess, err := session.NewSession(c)
		if err != nil {
			log.Fatal(err)
		}

		simulate.Simulate(log, sess)

	},
}

func init() { //nolint:gochecknoinits
	rootCmd.AddCommand(simulateCmd)
	simulateCmd.Flags().StringP("audit-file", "a", "", "File containing audits to run")
	simulateCmd.Flags().BoolP("ec2", "e", false, "Audit ec2 instances")
	simulateCmd.Flags().BoolP("ecs", "E", false, "Audit ecs tasks")
	simulateCmd.Flags().BoolP("lambda", "f", false, "Audit lambda functions")
	simulateCmd.Flags().BoolP("no-users", "n", false, "Skip auditing IAM users")

	bindParams := []string{
		"audit-file",
		"ec2",
		"ecs",
		"lambda",
		"no-users",
	}

	for _, param := range bindParams {
		if err := viper.BindPFlag(
			param, simulateCmd.Flags().Lookup(param)); err != nil {
			panic(fmt.Sprintf("cannot map config param '%s': %s", param, err.Error()))
		}
	}

	required := []string{"audit-file"}
	for _, param := range required {
		if err := simulateCmd.MarkFlagRequired(param); err != nil {
			panic(fmt.Sprintf("failed to set '%s' as required - '%s'", param, err.Error()))
		}
	}

}
