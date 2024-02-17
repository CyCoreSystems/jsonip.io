package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/CyCoreSystems/jsonip.io/service"
	"golang.org/x/crypto/acme/autocert"
)

var debug bool
var enableTLS bool
var listenPort uint

var listenDomains = []string{
	"jsonip.io",
	"ipv4.jsonip.io",
	"ipv6.jsonip.io",
}

func init() {
	flag.BoolVar(&debug, "debug", false, "enable debug mode")
	flag.BoolVar(&enableTLS, "tls", false, "whether to enable TLS")
	flag.UintVar(&listenPort, "port", 8080, "port on which to listen for HTTP traffic")
}

func main() {
	flag.Parse()

	logopts := &slog.HandlerOptions{
		Level:     func() slog.Level {
			if debug {
				return slog.LevelDebug
			}

			return slog.LevelInfo
		}(),
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, logopts))

	slog.SetDefault(logger)

	mux := service.NewServer()

	if enableTLS {
		go func() {
			slog.Info("listening (https) on 443")

			// Listen on HTTPS, with autocert
			slog.Error("failed to start TLS server: ", http.Serve(autocert.NewListener(listenDomains...), mux))

			panic("failed to start TLS listener")
		}()
	}

	// Listen on HTTP
	slog.Info("listening (http)", slog.Uint64("port", uint64(listenPort)))

	slog.Error("http listener failed:", http.ListenAndServe(fmt.Sprintf(":%d", listenPort), mux))

	panic("http listener failed")
}
