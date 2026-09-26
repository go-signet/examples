// Run from go-obo: go run ./cmd/cli
package main

import (
	"context"
	"github.com/go-signet/examples/go-obo/internal/demo"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := demo.LoadConfig("cli")
	if err != nil {
		log.Fatal(err)
	}
	err = demo.RunCLI(ctx, c, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}
