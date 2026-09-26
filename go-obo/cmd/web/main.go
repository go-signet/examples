// Run from go-obo: go run ./cmd/web
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
	c, err := demo.LoadConfig("web")
	if err != nil {
		log.Fatal(err)
	}
	app, err := demo.NewWeb(ctx, c)
	if err != nil {
		log.Fatal(err)
	}
	go app.RunMaintenance(ctx)
	err = demo.Serve(ctx, c.WebAddr, app.Handler())
	if err != nil {
		log.Fatal(err)
	}
}
