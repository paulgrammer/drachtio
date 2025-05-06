# drachtio-srf-go

A Go implementation of the [drachtio-srf](https://github.com/drachtio/drachtio-srf) SIP framework for [drachtio-server](https://github.com/drachtio/drachtio-server).

## Overview

This library provides a high-level API for building SIP applications using the Go programming language. It follows a similar architecture to the original JavaScript drachtio-srf, but with idiomatic Go patterns.

Key features:
- Connection to drachtio-server for SIP protocol handling
- Express-like middleware pattern for SIP message processing
- Support for all SIP methods: INVITE, REGISTER, MESSAGE, INFO, etc.
- Dialog management (establishing, maintaining, terminating SIP dialogs)
- Authentication support
- Registration handling

## Installation

```bash
go get github.com/paulgrammer/drachtio
```

## Quick Start

Below is a simple example of a SIP server that handles REGISTER requests with digest authentication:

```go
package main

import (
    "context"
    "flag"
    "log/slog"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/paulgrammer/drachtio"
)

func main() {
    // Set up connection parameters
    serverIP := flag.String("server", "localhost", "IP address of drachtio server")
    serverPort := flag.Int("port", 9022, "Port of drachtio server")
    secret := flag.String("secret", "cymru", "Shared secret for drachtio server")
    flag.Parse()

    // Set up logger
    logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))

    // Create and configure the SRF
    srf := drachtio.NewSrf(func(o *drachtio.ConnectionOptions) {
        o.Host = *serverIP
        o.Port = *serverPort
        o.Secret = *secret
        o.PingInterval = 5 * time.Second
    })

    defer srf.Disconnect()

    // Set up registry and authentication
    registry := drachtio.NewRegistry()
    registry.AddUser("alice", "password123")
    registry.AddUser("bob", "securepass456")

    digestAuth := drachtio.NewDigestAuth(registry, func(o *drachtio.DigestAuthOptions) {
        o.Realm = "drachtio"
        o.Algorithm = "MD5"
        o.NonceValidity = 5 * time.Minute
    })

    // Register handler for REGISTER requests
    srf.Register(digestAuth.Serve)

    // Start server
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    // Run registry service
    go registry.Run(ctx)
    defer registry.Stop()

    // Connect to drachtio server
    if err := srf.Connect(ctx); err != nil {
        logger.Error("Failed to run srf", "error", err)
    }

    <-ctx.Done()
    logger.Info("Shutting down gracefully")
}
```

## Example: Handling MESSAGE Requests

```go
package main

import (
    "context"
    "flag"
    "log/slog"
    "os"
    "os/signal"
    "syscall"

    "github.com/paulgrammer/drachtio"
)

func messageHandler(req *drachtio.SrfRequest, res *drachtio.SrfResponse) {
    logger := slog.Default()

    logger.Info("Received SIP MESSAGE",
        "from", req.From().Address.String(),
        "to", req.To().Address.String(),
        "body", string(req.Body()))

    // Reply with 200 OK
    res.Ok()
}

func main() {
    srf := drachtio.NewSrf(func(o *drachtio.ConnectionOptions) {
        o.Host = "localhost"
        o.Port = 9022
        o.Secret = "cymru"
    })

    defer srf.Disconnect()

    // Register handler for MESSAGE requests
    srf.Message(messageHandler)

    // Start server
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
    defer cancel()

    if err := srf.Connect(ctx); err != nil {
        slog.Error("Failed to run srf", "error", err)
    }

    <-ctx.Done()
}
```

## Example: Creating a B2BUA

```go
package main

import (
    "context"
    "log/slog"
    "os"
    "os/signal"
    "syscall"

    "github.com/paulgrammer/drachtio"
)

func inviteHandler(srf *drachtio.Srf, registry drachtio.RegistryType) drachtio.HandlerFunc {
    return func(req *drachtio.SrfRequest, res *drachtio.SrfResponse) {
        logger := slog.Default()

        // Find destination contact in registry
        entity, err := registry.RegistrationLookup(req.To().Address.String())
        if err != nil {
            logger.Error("Failed to find account", "error", err)
            res.NotFound(err.Error())
            return
        }

        if len(entity.Contacts) == 0 {
            logger.Error("Contact not found")
            res.NotFound("Contact not found")
            return
        }

        destination := entity.Contacts[0].Address
        logger.Info("Forwarding to destination", "destination", destination.String())

        // Create B2BUA (back-to-back user agent)
        uas, uac, err := srf.CreateB2BUA(req, res, destination, func(cu *drachtio.CreateB2BUAOptions) {
            cu.ProxyRequestHeaders = []string{"To", "From", "Content-Type", "Allow", "Supported"}
            cu.ProxyResponseHeaders = []string{"accept", "allow", "allow-events"}
        })

        if err != nil {
            logger.Error("Failed to create dialog", "error", err)
            res.InternalServerError(err.Error())
            return
        }

        // Handle dialog events
        uas.OnDestroy(func(d *drachtio.Dialog) {
            logger.Debug("UAS Dialog destroyed", "id", d.ID)
        })

        uac.OnDestroy(func(d *drachtio.Dialog) {
            logger.Debug("UAC Dialog destroyed", "id", d.ID)
        })
    }
}

func main() {
    // ... setup code similar to previous examples ...

    // B2BUA registering the INVITE handler
    srf.Invite(inviteHandler(srf, registry))

    // ... server startup code ...
}
```

## Example: Using INFO Method

```go
package main

import (
    "github.com/paulgrammer/drachtio"
)

func infoHandler(req *drachtio.SrfRequest, res *drachtio.SrfResponse) {
    logger := slog.Default()

    logger.Info("Received INFO request",
        "from", req.From().Address.String(),
        "content-type", req.GetHeader("Content-Type"),
        "body", string(req.Body()))

    // Process DTMF or other application data

    res.Ok()
}

func main() {
    // ... setup code ...

    // Register INFO handler
    srf.Info(infoHandler)

    // ... server startup code ...
}
```

## SIP Methods Supported

All standard SIP methods have been implemented:

- `srf.Invite()` - Handle INVITE requests
- `srf.Register()` - Handle REGISTER requests
- `srf.Message()` - Handle MESSAGE requests
- `srf.Info()` - Handle INFO requests
- `srf.Bye()` - Handle BYE requests
- `srf.Cancel()` - Handle CANCEL requests
- `srf.Options()` - Handle OPTIONS requests
- `srf.Notify()` - Handle NOTIFY requests
- `srf.Subscribe()` - Handle SUBSCRIBE requests
- `srf.Refer()` - Handle REFER requests
- `srf.Prack()` - Handle PRACK requests
- `srf.Update()` - Handle UPDATE requests

## Work in Progress

The following features are currently under development:

- Full User Agent implementations:
  - `srf.CreateUAS()` - Create a User Agent Server
  - `srf.CreateUAC()` - Create a User Agent Client
  - `srf.CreateB2BUA()` - Create a Back-to-Back User Agent (partial implementation available)
