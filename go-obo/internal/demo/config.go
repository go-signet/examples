// Package demo contains the application code shared by this example's four
// commands. It is intentionally private to the example, not an authentication SDK.
package demo

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

const (
	InputScope  = "orders.delegate.read"
	OutputScope = "orders.read"
)

type Config struct {
	Issuer, WebID, WebSecret, CLIID, AID, ASecret, BID, BSecret string
	AudienceA, AudienceB, URLA, URLB                            string
	WebAddr, AAddr, BAddr, WebRedirect, CLIAddr                 string
}

// LoadConfig validates only the credentials needed by the selected process.
func LoadConfig(role string) (Config, error) {
	_ = godotenv.Load()
	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	c := Config{
		Issuer:    os.Getenv("SIGNET_URL"),
		AudienceA: get("API_A_AUDIENCE", "https://api-a.example.com"), AudienceB: get("API_B_AUDIENCE", "https://api-b.example.com"),
		URLA: get("API_A_URL", "http://127.0.0.1:8091"), URLB: get("API_B_URL", "http://127.0.0.1:8092"),
		WebAddr: get("WEB_ADDR", "127.0.0.1:8090"), AAddr: get("API_A_ADDR", "127.0.0.1:8091"), BAddr: get("API_B_ADDR", "127.0.0.1:8092"),
		WebRedirect: get("WEB_REDIRECT_URL", "http://127.0.0.1:8090/callback"), CLIAddr: get("CLI_CALLBACK_ADDR", "127.0.0.1:8093"),
	}
	required := map[string]string{"SIGNET_URL": c.Issuer}
	urls := map[string]string{"SIGNET_URL": c.Issuer, "API_A_AUDIENCE": c.AudienceA, "API_B_AUDIENCE": c.AudienceB}
	switch role {
	case "web":
		c.WebID, c.WebSecret = os.Getenv("WEB_CLIENT_ID"), os.Getenv("WEB_CLIENT_SECRET")
		required["WEB_CLIENT_ID"], required["WEB_CLIENT_SECRET"] = c.WebID, c.WebSecret
		urls["API_A_URL"], urls["WEB_REDIRECT_URL"] = c.URLA, c.WebRedirect
	case "cli":
		c.CLIID = os.Getenv("CLI_CLIENT_ID")
		required["CLI_CLIENT_ID"] = c.CLIID
		urls["API_A_URL"] = c.URLA
	case "api-a":
		c.AID, c.ASecret = os.Getenv("API_A_CLIENT_ID"), os.Getenv("API_A_CLIENT_SECRET")
		required["API_A_CLIENT_ID"], required["API_A_CLIENT_SECRET"] = c.AID, c.ASecret
		urls["API_B_URL"] = c.URLB
	case "api-b":
		c.AID, c.BID, c.BSecret = os.Getenv("API_A_CLIENT_ID"), os.Getenv("API_B_CLIENT_ID"), os.Getenv("API_B_CLIENT_SECRET")
		required["API_A_CLIENT_ID"], required["API_B_CLIENT_ID"], required["API_B_CLIENT_SECRET"] = c.AID, c.BID, c.BSecret
	default:
		return c, fmt.Errorf("unknown process role")
	}
	for k, v := range required {
		if strings.TrimSpace(v) == "" {
			return c, fmt.Errorf("set %s", k)
		}
	}
	for k, v := range urls {
		if _, err := safeURL(v); err != nil {
			return c, fmt.Errorf("%s must be an absolute HTTPS URL (HTTP only on loopback), without credentials, query or fragment", k)
		}
	}
	if c.AudienceA == c.AudienceB {
		return c, fmt.Errorf("API audiences must differ")
	}
	if role == "cli" {
		host, port, err := net.SplitHostPort(c.CLIAddr)
		if err != nil || !loopback(host) || port == "" || port == "0" {
			return c, fmt.Errorf("CLI_CALLBACK_ADDR must use a loopback host and fixed port")
		}
	}
	if role == "web" {
		u, _ := url.Parse(c.WebRedirect)
		if u.Path != "/callback" {
			return c, fmt.Errorf("WEB_REDIRECT_URL path must be /callback")
		}
	}
	return c, nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func safeURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") ||
		(u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return nil, fmt.Errorf("unsafe URL")
	}
	return u, nil
}
