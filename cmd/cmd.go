package main

import (
	"log"
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

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/ossign/config.yaml", "config file (default is /etc/ossign/config.yaml)")

	// Signing flags
	rootCmd.Flags().StringVarP((*string)(&GlobalConfig.SignatureType), "sign-type", "t", "", "Type of file to sign (powershell, pecoff, authenticode, dmg, auto)")
	rootCmd.Flags().StringVarP(&GlobalConfig.OutputFile, "output", "o", "", "Output file for the signed binary (Default: [inputFile]-signed[.ext])")
}

func initConfig() {
	cfgPath, err := filepath.Abs(filepath.Dir(cfgFile))
	if err != nil {
		log.Fatal(err)
	}

	viper.SetConfigName("config")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		configDir := path.Dir(cfgFile)
		if configDir != "." && configDir != cfgPath {
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
