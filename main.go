package main

import (
    "flag"
    "fmt"
    log "github.com/sirupsen/logrus"
    "github.com/docker/go-plugins-helpers/secrets"
)

func main() {
    var (
        flVersion = flag.Bool("version", false, "Print version")
        flDebug   = flag.Bool("debug", false, "Enable debug logging")
    )
    flag.Parse()

    if *flVersion {
        fmt.Println("Vault Secrets Provider v1.0.0")
        return
    }

    if *flDebug {
        log.SetLevel(log.DebugLevel)
    }

    // Initialize the Vault driver
    driver, err := NewVaultDriver()
    if err != nil {
        log.Fatalf("Failed to initialize vault driver: %v", err)
    }

    // Create the plugin handler
    handler := secrets.NewHandler(driver)

    // Serve the plugin - must match config.json socket name
    log.Println("Starting Vault secrets provider plugin...")
    if err := handler.ServeUnix("plugin", 0); err != nil {
        log.Fatalf("Failed to serve plugin: %v", err)
    }
}