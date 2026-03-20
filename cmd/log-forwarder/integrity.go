package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type VerifyResponse struct {
	Valid        bool   `json:"valid"`
	TotalEntries uint64 `json:"totalEntries"`
}

func VerifyEndpointFromLogsEndpoint(logsEndpoint string) (string, error) {
	u, err := url.Parse(logsEndpoint)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid logs endpoint")
	}

	if strings.Contains(u.Path, "/v1/logs") {
		u.Path = strings.Replace(u.Path, "/v1/logs", "/v1/verify", 1)
	} else {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/verify"
	}
	u.RawQuery = ""
	return u.String(), nil
}

func StartIntegrityVerifier(ctx context.Context, logger *log.Logger, logsEndpoint string, timeout time.Duration, interval time.Duration) {
	verifyEndpoint, err := VerifyEndpointFromLogsEndpoint(logsEndpoint)
	if err != nil {
		logger.Printf("event=verify_init_failed err=%q", err)
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: timeout}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyEndpoint, nil)
			if err != nil {
				logger.Printf("event=verify_request_build_failed err=%q", err)
				continue
			}
			res, err := client.Do(req)
			if err != nil {
				logger.Printf("event=verify_request_failed err=%q", err)
				continue
			}
			body, readErr := io.ReadAll(res.Body)
			res.Body.Close()
			if readErr != nil {
				logger.Printf("event=verify_read_failed err=%q", readErr)
				continue
			}
			if res.StatusCode >= 300 {
				logger.Printf("event=verify_bad_status status=%d body=%q", res.StatusCode, strings.TrimSpace(string(body)))
				continue
			}

			var out VerifyResponse
			if err := json.Unmarshal(body, &out); err != nil {
				logger.Printf("event=verify_decode_failed err=%q", err)
				continue
			}

			logger.Printf("event=verify_result valid=%t total_entries=%d endpoint=%q", out.Valid, out.TotalEntries, verifyEndpoint)
		}
	}
}
