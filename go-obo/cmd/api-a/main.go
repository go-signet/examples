// Run from go-obo: go run ./cmd/api-a
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
	c, err := demo.LoadConfig("api-a")
	if err != nil {
		log.Fatal(err)
	}
	app, err := demo.NewAPI(ctx, c, false)
	if err != nil {
		log.Fatal(err)
	}
	err = demo.Serve(ctx, c.AAddr, app.Handler())
	if err != nil {
		log.Fatal(err)
	}
}
