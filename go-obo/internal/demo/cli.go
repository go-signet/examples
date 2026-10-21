package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RunCLI deliberately uses Authorization Code + PKCE, not Device Flow: Signet's
// combined consent screen is part of the authorization-code browser flow.
func RunCLI(ctx context.Context, c Config, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	flow, err := newLogin(ctx, c, true)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", c.CLIAddr)
	if err != nil {
		return errors.New("cannot listen on CLI_CALLBACK_ADDR")
	}
	tx, authURL := flow.start()
	type outcome struct {
		login *loginResult
		err   error
	}
	results := make(chan outcome, 1)
	var mu sync.Mutex
	used := false
	m := http.NewServeMux()
	m.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || !validState(tx, q) {
			writeError(w, fail(400, "invalid_state"))
			return
		}
		mu.Lock()
		if used {
			mu.Unlock()
			writeError(w, fail(400, "callback_already_used"))
			return
		}
		used = true
		mu.Unlock()
		login, err := flow.finish(r.Context(), tx, q)
		if err != nil {
			writeError(w, err)
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "Signed in. Return to your terminal; you may close this tab.")
		}
		results <- outcome{login, err}
	})
	s := server(c.CLIAddr, m)
	s.BaseContext = func(net.Listener) context.Context { return ctx }
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- s.Serve(l) }()
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if s.Shutdown(stop) != nil {
			_ = s.Close()
		}
	}()
	// No credentials or tokens are in this URL, only OAuth request metadata.
	fmt.Fprintln(out, "Open this URL in a browser on this computer (expires in five minutes):")
	fmt.Fprintln(out, authURL)
	select {
	case <-ctx.Done():
		return errors.New("login cancelled or timed out")
	case <-serveErrors:
		return errors.New("callback server stopped")
	case result := <-results:
		if result.err != nil {
			return result.err
		}
		orders, err := fetchOrders(ctx, flow.http, c.URLA, result.login.Token)
		if err != nil {
			return err
		}
		if orders.Source == nil || orders.Source.Subject != result.login.Identity.Subject || orders.Downstream.Subject != result.login.Identity.Subject {
			return fail(502, "subject_mismatch")
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(orders)
	}
}
