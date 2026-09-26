// Run from go-obo: go run ./cmd/api-b
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
	c, err := demo.LoadConfig("api-b")
	if err != nil {
		log.Fatal(err)
	}
	app, err := demo.NewAPI(ctx, c, true)
	if err != nil {
		log.Fatal(err)
	}
	err = demo.Serve(ctx, c.BAddr, app.Handler())
	if err != nil {
		log.Fatal(err)
	}
}
