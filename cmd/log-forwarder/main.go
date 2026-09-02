package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	auditclient "audit-logging/clients/go-lib"
)

func main() {
	configPath := flag.String("config", "./configs/log-forwarder.json", "Path to JSON config file")
	validateOnly := flag.Bool("validate-only", false, "Validate config and exit")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("event=config_load status=failed path=%q err=%q", *configPath, err)
	}

	httpClient := &http.Client{Timeout: time.Duration(cfg.RequestTimeoutMS) * time.Millisecond}
	client := auditclient.New(cfg.ServerURL, httpClient)
	client.AuthToken = cfg.AuthBearerToken
	client.Retry = auditclient.RetryConfig{
		MaxAttempts:    cfg.RetryMaxAttempts,
		InitialBackoff: time.Duration(cfg.RetryInitialBackoffMS) * time.Millisecond,
		MaxBackoff:     time.Duration(cfg.RetryMaxBackoffMS) * time.Millisecond,
		MaxJitter:      100 * time.Millisecond,
		JitterStrategy: auditclient.JitterFull,
	}

	if *validateOnly {
		log.Printf("event=config_validate status=ok config=%q", *configPath)
		return
	}

	parser, err := NewLineParser(cfg)
	if err != nil {
		log.Fatalf("event=parser_init status=failed err=%q", err)
	}

	metrics := NewRuntimeMetrics()
	client.OnRetry = func(attempt int, delay time.Duration, retryErr error) {
		metrics.IncRetries()
		log.Printf("event=delivery_retry attempt=%d delay_ms=%d err=%q", attempt, delay.Milliseconds(), retryErr)
	}

	log.Printf(
		"event=startup status=ok mode=m6 server_url=%q source_file=%q app_name=%q parser_mode=%q poll_interval_ms=%d batch_size=%d checkpoint_path=%q",
		cfg.ServerURL,
		cfg.SourceFile,
		cfg.AppName,
		cfg.ParserMode,
		cfg.PollIntervalMS,
		cfg.BatchSize,
		cfg.CheckpointPath,
	)
	log.Printf("event=runtime status=active note=%q", "M6 runtime metrics and integrity verifier enabled")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if cfg.MetricsPort > 0 {
		StartMetricsServer(ctx, log.Default(), cfg.MetricsPort, metrics)
	}
	go StartMetricsReporter(ctx, log.Default(), time.Duration(cfg.MetricsReportIntervalMS)*time.Millisecond, metrics)
	go StartIntegrityVerifier(ctx, log.Default(), cfg.ServerURL, cfg.AuthBearerToken, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond, time.Duration(cfg.VerifyIntervalMS)*time.Millisecond)

	follower := NewFollower(cfg, log.Default())
	err = follower.Run(ctx, func(event TailEvent) error {
		metrics.IncLinesRead()

		parsed, err := parser.Parse(event)
		if err != nil {
			metrics.IncParseFailed()
			log.Printf("event=parse_failed source_file=%q offset=%d err=%q", event.SourceFile, event.CommittedOffset, err)
			return nil
		}
		metrics.IncParsedOK()

		idempotencyKey := ComputeIdempotencyKey(parsed.App, parsed.SourceFile, parsed.SourceOffset, parsed.RawLine)
		if metrics.MarkIdempotencyKey(idempotencyKey) {
			log.Printf("event=duplicate_idempotency_key source_file=%q offset=%d key=%q", parsed.SourceFile, parsed.SourceOffset, idempotencyKey)
		}
		payload := BuildPayload(parsed, idempotencyKey)

		log.Printf("event=line_normalized source_file=%q offset=%d app=%q level=%q message_bytes=%d parser_mode=%q",
			parsed.SourceFile,
			parsed.SourceOffset,
			payload.App,
			payload.Level,
			len(payload.Message),
			parsed.ParserMode,
		)

		result, err := DeliverParsedEvent(ctx, cfg, client, parsed)
		if err != nil {
			metrics.IncDeliveryFailed()
			if dlErr := WriteDeadLetter(cfg.DeadLetterPath, payload, parsed.SourceFile, parsed.SourceOffset, err); dlErr != nil {
				log.Printf("event=deadletter_write_failed source_file=%q offset=%d err=%q", parsed.SourceFile, parsed.SourceOffset, dlErr)
				return dlErr
			}
			metrics.IncDeadLetterWrites()
			log.Printf("event=delivery_failed_deadlettered source_file=%q offset=%d err=%q", parsed.SourceFile, parsed.SourceOffset, err)
			return nil
		}
		metrics.IncDeliverySuccess()

		log.Printf("event=delivery_success source_file=%q offset=%d remote_index=%d entry_hash=%q", parsed.SourceFile, parsed.SourceOffset, result.Index, result.EntryHash)
		return nil
	})
	if err != nil {
		log.Fatalf("event=follower status=failed err=%q", err)
	}

	log.Printf("event=shutdown status=ok")
}
