package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	auditclient "audit-logging/clients/go-lib"
)

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	endpoint := getEnv("AUDIT_LOG_URL", "http://localhost:8090/v1/logs")
	appName := getEnv("AUDIT_APP_NAME", "go-producer")
	client := auditclient.New(endpoint, nil)
	client.AuthToken = getEnv("AUDIT_TOKEN", "")

	result, err := client.WriteLog(context.Background(), auditclient.LogRequest{
		App:     appName,
		Level:   "INFO",
		Message: "example log from Go producer",
		Metadata: map[string]any{
			"service":   appName,
			"emittedAt": time.Now().UTC().Format(time.RFC3339Nano),
			"traceId":   "trace-go-123",
		},
	})
	if err != nil {
		log.Fatalf("write log: %v", err)
	}

	fmt.Printf("log accepted: index=%d entryHash=%s\n", result.Index, result.EntryHash)
}
