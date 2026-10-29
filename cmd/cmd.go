package main

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "ossign [file1]",
	Short: "Sign binaries and other files using OSSign",
	Args:  cobra.MaximumNArgs(1),
	Run:   Run,
}

var cfgFile string

var GlobalConfig SigningConfig

func init() {
	cobra.OnInitialize(setupLogging, initConfig)

	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ~/.ossign/config.yaml, then ~/ossign/config.yaml)")

	// Signing flags
	rootCmd.Flags().StringVarP((*string)(&GlobalConfig.SignatureType), "sign-type", "t", "", "Type of file to sign (powershell, pecoff, authenticode, dmg, auto)")
	rootCmd.Flags().StringVarP(&GlobalConfig.OutputFile, "output", "o", "", "Output file for the signed binary (default: sign in place, overwriting the input)")
}

func initConfig() {
	if os.Getenv("OSSIGN_CONFIG") != "" || os.Getenv("OSSIGN_CONFIG_BASE64") != "" {
		var config []byte
		if os.Getenv("OSSIGN_CONFIG_BASE64") != "" {
			slog.Info("Using config from OSSIGN_CONFIG_BASE64 environment variable")
			configBytes, err := base64.StdEncoding.DecodeString(os.Getenv("OSSIGN_CONFIG_BASE64"))
			if err != nil {
				fatal("Error decoding OSSIGN_CONFIG_BASE64", "error", err)
			}
			config = configBytes
		} else {
			slog.Info("Using config from OSSIGN_CONFIG environment variable")
			config = []byte(os.Getenv("OSSIGN_CONFIG"))
		}

		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(config), &decoded); err == nil {
			viper.MergeConfigMap(decoded)
		} else {
			fatal("Error parsing OSSIGN_CONFIG/OSSIGN_CONFIG_BASE64", "error", err)
		}

		err := viper.Unmarshal(&GlobalConfig)
		if err != nil {
			fatal("Unable to decode config", "error", err)
		}

		return
	}

	if cfgFile == "" {
		cfgFile = defaultConfigFile()
	}
	slog.Debug("Resolved config file", "path", cfgFile)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// For Windows, use ProgramData
		programdir := "/etc/ossign"
		if os.Getenv("ProgramData") != "" {
			programdir = filepath.Join(os.Getenv("ProgramData"), "ossign")
		}

		viper.AddConfigPath(programdir)
		viper.SetConfigName("config")
	}

	if err := viper.ReadInConfig(); err == nil {
		err := viper.Unmarshal(&GlobalConfig)
		if err != nil {
			fatal("Unable to decode config", "error", err)
		}
		slog.Info("Using config file", "path", viper.ConfigFileUsed())
	} else {
		slog.Warn("No config file found, trying to proceed without it", "error", err)
	}
}

// defaultConfigFile returns the first existing config file in the user's home
// directory, checking ~/.ossign/config.yaml before ~/ossign/config.yaml.
func defaultConfigFile() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	for _, file := range []string{".ossign/config.yaml", "ossign/config.yaml", ".ossign/config.yml", "ossign/config.yml"} {
		path := filepath.Join(homedir, file)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}
