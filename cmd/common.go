// Package cmd - Holds reusable code for this package
package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	logger "github.com/mtlang/Policy-Urchin/log"
)

// CheckRequiredFlags - Returns an error if a required flag is not set
// This function was found here:
// https://github.com/spf13/cobra/issues/206#issuecomment-322743645
func CheckRequiredFlags(cmd *cobra.Command, _ []string) error {
	flags := cmd.Flags()
	missingFlagNames := []string{}

	flags.VisitAll(func(flag *pflag.Flag) {
		requiredAnnotation, found := flag.Annotations[cobra.BashCompOneRequiredFlag]
		if !found {
			return
		}

		if (requiredAnnotation[0] == "true") && !flag.Changed {
			missingFlagNames = append(missingFlagNames, flag.Name)
		}
	})

	if len(missingFlagNames) > 0 {
		return fmt.Errorf("required flag \"%s\" has not been set", strings.Join(missingFlagNames, "\", \""))
	}

	return nil
}

// GetLogger - return a default logger instance
func GetLogger(v *viper.Viper) logger.Logger {
	var zconfig zap.Config
	var level zapcore.Level
	if v.GetBool("production") {
		zconfig = zap.NewProductionConfig()
		zconfig.OutputPaths = []string{v.GetString("log-file")}
	} else {
		zconfig = zap.NewDevelopmentConfig()
		zconfig.EncoderConfig.EncodeLevel = zapcore.LowercaseColorLevelEncoder
	}

	if err := level.Set(v.GetString("log-level")); err != nil {
		panic(err)
	}
	zconfig.Level = zap.NewAtomicLevelAt(level)
	// sometimes we want tot skip stack traces in dev mode too...
	if v.GetBool("verbose") {
		zconfig.DisableStacktrace = true
	}

	logger, _ := zconfig.Build()
	defer func() {
		_ = logger.Sync() // flushes buffer, if any
	}()
	return logger.Sugar()
}
