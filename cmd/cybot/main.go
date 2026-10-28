package main

import (
	"fmt"
	"os"

	"github.com/s41r4j/cybot/internal/app"
)

var version = "dev"

func main() {
	if err := app.NewCommand(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
