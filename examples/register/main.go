package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/paulgrammer/drachtio"
)

const (
	globalVarKey    = "some-global-var"
	globalLoggerKey = "logger"
)

func getLoggerFromReq(req *drachtio.SrfRequest) *slog.Logger {
	return req.MustGet(globalLoggerKey).(*slog.Logger)
}

func globalMiddlewareFn(logger *slog.Logger) drachtio.HandlerFunc {
	return func(req *drachtio.SrfRequest, res *drachtio.SrfResponse) {
		req.Set(globalVarKey, "global config here")
		req.Set(globalLoggerKey, logger)
	}
}

func loggingMiddleware(req *drachtio.SrfRequest, res *drachtio.SrfResponse) {
	logger := getLoggerFromReq(req)

	logger.Info("SIP request",
		"method", string(req.Method()),
		"Call-ID", req.CallID().Value(),
		"from", req.From().Address.String(),
		"to", req.To().Address.String())
}

func main() {
	serverIP := flag.String("server", "localhost", "IP address of drachtio server")
	serverPort := flag.Int("port", 9022, "Port of drachtio server")
	secret := flag.String("secret", "cymru", "Shared secret for drachtio server")
	flag.Parse()

	// Set up slog
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	logger := slog.New(logHandler)

	srf := drachtio.NewSrf(func(o *drachtio.ConnectionOptions) {
		o.Host = *serverIP
		o.Port = *serverPort
		o.Secret = *secret
		o.PingInterval = 5 * time.Second
		o.Tags = make([]string, 0)
	})

	defer srf.Disconnect()

	// Registration setup
	registry := drachtio.NewRegistry()

	registry.OnRegistration(func(reg *drachtio.Registration) {
		logger.Debug("Registered",
			"aor", reg.AOR,
			"contact", reg.Contacts[0].Address.String(),
			"expires", reg.ExpiresAt)
	})

	// Add some test users
	registry.AddUser("alice", "password123")
	registry.AddUser("bob", "securepass456")
	registry.AddUser("carol", "letmein789")

	digestAuth := drachtio.NewDigestAuth(registry, func(o *drachtio.DigestAuthOptions) {
		o.Realm = "drachtio"
		o.Opaque = "drachtio"
		o.Algorithm = "MD5"
		o.Secret = "v99UTErumDE4wmVgqWRagA6kWHfDemKS"
		o.NonceValidity = 5 * time.Minute
	})

	// Global middleware
	srf.Use(globalMiddlewareFn(logger), loggingMiddleware)

	// Routes
	srf.Register(digestAuth.Serve)

	// Run
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	go registry.Run(ctx)
	defer registry.Stop()

	if err := srf.Connect(ctx); err != nil {
		logger.Error("Failed to run srf", "error", err)
	}

	<-ctx.Done()
	logger.Info("Shutting down gracefully")
}
