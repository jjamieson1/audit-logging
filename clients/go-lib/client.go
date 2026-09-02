package auditclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

type LogRequest struct {
	App      string         `json:"app"`
	Level    string         `json:"level"`
	Message  string         `json:"message"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type LogResponse struct {
	Index     uint64 `json:"index"`
	Timestamp string `json:"timestamp"`
	EntryHash string `json:"entryHash"`
	PrevHash  string `json:"prevHash"`
}

type Client struct {
	Endpoint   string
	HTTPClient *http.Client
	Retry      RetryConfig
	AuthToken  string
	Headers    map[string]string
	OnRetry    func(attempt int, delay time.Duration, err error)
}

type RetryConfig struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxJitter      time.Duration
	JitterStrategy JitterStrategy
}

type JitterStrategy string

const (
	JitterFull         JitterStrategy = "full"
	JitterEqual        JitterStrategy = "equal"
	JitterDecorrelated JitterStrategy = "decorrelated"
)

func New(endpoint string, httpClient *http.Client) *Client {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "http://localhost:8080/v1/logs"
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
		Retry: RetryConfig{
			MaxAttempts:    1,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     2 * time.Second,
			MaxJitter:      100 * time.Millisecond,
			JitterStrategy: JitterFull,
		},
	}
}

func (c *Client) WriteLog(ctx context.Context, payload LogRequest) (LogResponse, error) {
	payload.App = strings.TrimSpace(payload.App)
	payload.Level = strings.TrimSpace(payload.Level)
	payload.Message = strings.TrimSpace(payload.Message)
	if payload.App == "" || payload.Level == "" || payload.Message == "" {
		return LogResponse{}, fmt.Errorf("app, level, and message are required")
	}
	if payload.Metadata == nil {
		payload.Metadata = map[string]any{}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return LogResponse{}, err
	}

	maxAttempts := c.Retry.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	initialBackoff := c.Retry.InitialBackoff
	if initialBackoff <= 0 {
		initialBackoff = 100 * time.Millisecond
	}

	maxBackoff := c.Retry.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 2 * time.Second
	}

	maxJitter := c.Retry.MaxJitter
	if maxJitter < 0 {
		maxJitter = 0
	}

	jitterStrategy := normalizeJitterStrategy(c.Retry.JitterStrategy)

	backoff := initialBackoff
	previousDelay := initialBackoff
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
		if err != nil {
			return LogResponse{}, err
		}
		req.Header.Set("content-type", "application/json")
		if strings.TrimSpace(c.AuthToken) != "" {
			req.Header.Set("authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
		}
		for key, value := range c.Headers {
			if strings.TrimSpace(key) == "" {
				continue
			}
			req.Header.Set(key, value)
		}

		res, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			resBody, readErr := io.ReadAll(res.Body)
			res.Body.Close()
			if readErr != nil {
				lastErr = readErr
			} else if res.StatusCode >= 300 {
				lastErr = fmt.Errorf("audit service returned %d: %s", res.StatusCode, strings.TrimSpace(string(resBody)))
				if !shouldRetryStatus(res.StatusCode) {
					return LogResponse{}, lastErr
				}
			} else {
				var out LogResponse
				if err := json.Unmarshal(resBody, &out); err != nil {
					return LogResponse{}, fmt.Errorf("parse response: %w", err)
				}
				return out, nil
			}
		}

		if attempt == maxAttempts {
			break
		}

		delay := computeRetryDelay(backoff, previousDelay, initialBackoff, maxBackoff, maxJitter, jitterStrategy)
		if c.OnRetry != nil {
			c.OnRetry(attempt, delay, lastErr)
		}
		if err := sleepWithContext(ctx, delay); err != nil {
			return LogResponse{}, err
		}
		previousDelay = delay

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("failed to write log")
	}

	return LogResponse{}, lastErr
}

func shouldRetryStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}

	return time.Duration(rand.Int63n(int64(max) + 1))
}

func normalizeJitterStrategy(strategy JitterStrategy) JitterStrategy {
	switch strategy {
	case JitterEqual, JitterDecorrelated:
		return strategy
	default:
		return JitterFull
	}
}

func computeRetryDelay(base, previousDelay, initialBackoff, maxBackoff, maxJitter time.Duration, strategy JitterStrategy) time.Duration {
	switch strategy {
	case JitterEqual:
		half := maxJitter / 2
		return base + half + randomJitter(half)
	case JitterDecorrelated:
		lower := initialBackoff
		upper := previousDelay * 3
		if upper < lower {
			upper = lower
		}
		if upper > maxBackoff {
			upper = maxBackoff
		}
		if maxJitter > 0 {
			jitterCap := lower + maxJitter
			if jitterCap < upper {
				upper = jitterCap
			}
		}
		return randomDuration(lower, upper)
	default:
		return base + randomJitter(maxJitter)
	}
}

func randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}

	delta := max - min
	return min + time.Duration(rand.Int63n(int64(delta)+1))
}
