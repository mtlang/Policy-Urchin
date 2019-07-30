package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "policy-urchin",
	Short: "Policy-Urchin: a suite of tools for auditing AWS access.",
	Long:  `Policy-Urchin: a suite of tools for auditing AWS access.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().
		StringP("cache-file", "c", "cache/cache.json", "Cache file")
	rootCmd.PersistentFlags().
		StringP("log-file", "l", "policy.log", "log file path")
	rootCmd.PersistentFlags().
		StringP("log-level", "L", "info", "supports info, debug, error, and warn")
	rootCmd.PersistentFlags().
		StringP("output", "o", "", "Output results to file")

	bindParams := []string{
		"cache-file",
		"log-file",
		"log-level",
		"output",
	}

	for _, param := range bindParams {
		if err := viper.BindPFlag(
			param, rootCmd.PersistentFlags().Lookup(param)); err != nil {
			panic(fmt.Sprintf("cannot map config param '%s': %s\n", param, err.Error()))
		}
	}
}
