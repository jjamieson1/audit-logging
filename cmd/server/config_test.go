package main

import "testing"

func TestLoadConfigListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		bindAddr string
		port     string
		want     string
	}{
		{name: "defaults to all interfaces", bindAddr: "", port: "", want: ":8080"},
		{name: "binds loopback when set", bindAddr: "127.0.0.1", port: "8080", want: "127.0.0.1:8080"},
		{name: "honours custom port", bindAddr: "127.0.0.1", port: "9090", want: "127.0.0.1:9090"},
		{name: "trims surrounding whitespace", bindAddr: "  127.0.0.1  ", port: "", want: "127.0.0.1:8080"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BIND_ADDR", tc.bindAddr)
			t.Setenv("PORT", tc.port)

			if got := loadConfig().ListenAddr(); got != tc.want {
				t.Fatalf("ListenAddr() = %q, want %q", got, tc.want)
			}
		})
	}
}
