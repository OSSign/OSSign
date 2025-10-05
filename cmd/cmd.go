package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path"
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
	cobra.OnInitialize(initConfig)

	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", filepath.Join(homedir, ".ossign/config.yaml"), "config file (default is ~/ossign/config.yaml)")

	// Signing flags
	rootCmd.Flags().StringVarP((*string)(&GlobalConfig.SignatureType), "sign-type", "t", "", "Type of file to sign (powershell, pecoff, authenticode, dmg, auto)")
	rootCmd.Flags().StringVarP(&GlobalConfig.OutputFile, "output", "o", "", "Output file for the signed binary (Default: [inputFile]-signed[.ext])")
}

func initConfig() {
	if os.Getenv("OSSIGN_CONFIG") != "" || os.Getenv("OSSIGN_CONFIG_BASE64") != "" {
		var config []byte
		if os.Getenv("OSSIGN_CONFIG_BASE64") != "" {
			configBytes, err := base64.StdEncoding.DecodeString(os.Getenv("OSSIGN_CONFIG_BASE64"))
			if err != nil {
				log.Fatalf("Error decoding OSSIGN_CONFIG_BASE64: %v", err)
			}
			config = configBytes
		} else {
			config = []byte(os.Getenv("OSSIGN_CONFIG"))
		}

		var decoded SigningConfig
		if err := json.Unmarshal([]byte(config), &decoded); err == nil {
			GlobalConfig = decoded
			log.Println("Using config from OSSIGN_CONFIG/OSSIGN_CONFIG_BASE64 environment variable")
			return
		}

		log.Println("Using config from OSSIGN_CONFIG environment variable")

		err := viper.Unmarshal(&GlobalConfig)
		if err != nil {
			log.Fatal("Unable to decode into struct:", err)
		}

		return
	}

	cfgPath, err := filepath.Abs(filepath.Dir(cfgFile))
	if err != nil {
		log.Fatal(err)
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	abspath := filepath.Join(homedir, ".ossign")

	viper.AddConfigPath(abspath)

	viper.SetConfigName("config")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		configDir := path.Dir(cfgPath)
		if configDir != "." && configDir != abspath {
			viper.AddConfigPath(configDir)
		}
	}

	if err := viper.ReadInConfig(); err == nil {
		err := viper.Unmarshal(&GlobalConfig)
		if err != nil {
			log.Fatal("Unable to decode into struct:", err)
		}
		log.Println("Using config file:", viper.ConfigFileUsed())
	} else {
		log.Println("No config file found, proceeding without it")
	}
}
