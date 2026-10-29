package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"proxy/internal/config"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "config: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "./configs/proxy.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, warnings, err := config.Load(*path)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	b, err := json.Marshal(cfg.Redacted())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s\n", b)
	return nil
}
