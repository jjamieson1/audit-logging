package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStartIntegrityVerifierSendsBearerHeaderWhenConfigured(t *testing.T) {
	t.Parallel()

	authCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case authCh <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"valid":true,"totalEntries":1}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go StartIntegrityVerifier(ctx, log.New(ioDiscard{}, "", 0), srv.URL+"/v1/logs", "secret-token", time.Second, 10*time.Millisecond)

	select {
	case got := <-authCh:
		want := "Bearer secret-token"
		if got != want {
			t.Fatalf("Authorization header = %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for verify request")
	}
}

func TestStartIntegrityVerifierOmitsHeaderWhenTokenEmpty(t *testing.T) {
	t.Parallel()

	authCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case authCh <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"valid":true,"totalEntries":1}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go StartIntegrityVerifier(ctx, log.New(ioDiscard{}, "", 0), srv.URL+"/v1/logs", "", time.Second, 10*time.Millisecond)

	select {
	case got := <-authCh:
		if got != "" {
			t.Fatalf("Authorization header = %q, want no header set", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for verify request")
	}
}
