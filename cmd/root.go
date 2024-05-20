// Copyright PuffinSecurity 2024

package cmd

import (
	"log"
	
	"github.com/spf13/cobra"

	"puffinsecurity/dustids/engine"
)

var (
	AppName   = "Dust IDS"
	Version   = "v0.0.0"
	BuildHash = "devel"
	BuildDate = "1970-01-01T00:00:00Z"
)

var RootCmd = &cobra.Command{
	Use:   "",
	Short: "Dust IDS",
	PreRun: func(cmd *cobra.Command, args []string) {
		if val, err := cmd.Flags().GetBool("version"); err == nil && val {
			fmt.Printf("%s %s\nBuilt datetime: %s\nBuild Hash: %s\n", AppName, Version, BuildDate, BuildHash)
			os.Exit(0)
		} else if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		err := logger.New()
		if err != nil {
			fmt.Printf("Err: %s\n", err.Error())
		}
	},

	Run: runEngine,
}

func runEngine (cmd *cobra.Command, args []string) {
	// later log .Log.Info("starting dust ids")
	// Ensure user is root
	ensureRoot()

	// Start dust engine
	motor, err := engine.Create()
	if err != nil {
		logger.Log.Fatalf("unable to initiate yara engine: %s", err.Error())
	}

	motor.Start()
}


func ensureRoot() {
	switch runtime.GOOS {
	case "windows":
		_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			logger.Log.Fatal("Run Dust as Administrator user")
		}
	case "darwin":
		fallthrough
	case "linux":
		if uid := syscall.Getuid(); uid != 0 {
			logger.Log.Fatal("Run Dust as root user")

		}
	}
}
