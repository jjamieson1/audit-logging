package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

const clientsUsage = `Usage: audit clients <command> [flags]

Commands:
  register --name <name> [--role client|admin]   Create a client and mint its token
  list                                           Show every client
  rotate --id <clientId>                         Issue a new token for a client
  revoke --id <clientId>                         Disable a client's token

DATABASE_URL must be set. The registry always lives in PostgreSQL.`

// runClientsCLI executes an admin subcommand against a registry. It takes the
// store and the output stream as arguments so it is testable without a
// database. The return value is the process exit code.
func runClientsCLI(store ClientStore, args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, clientsUsage)
		return 2
	}

	switch args[0] {
	case "register":
		return clientsRegister(store, args[1:], out)
	case "list":
		return clientsList(store, out)
	case "rotate":
		return clientsRotate(store, args[1:], out)
	case "revoke":
		return clientsRevoke(store, args[1:], out)
	default:
		fmt.Fprintf(out, "unknown command %q\n\n%s\n", args[0], clientsUsage)
		return 2
	}
}

func clientsRegister(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients register", flag.ContinueOnError)
	flags.SetOutput(out)
	name := flags.String("name", "", "human-readable client name (required)")
	role := flags.String("role", RoleClient, "client or admin")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	clientID, token, err := store.Register(*name, *role)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "client id: %s\n", clientID)
	fmt.Fprintf(out, "token:     %s\n", token)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Give this token to the client now. Only its hash is stored, so the")
	fmt.Fprintln(out, "token is not recoverable. If it is lost, run: audit clients rotate")

	return 0
}

func clientsList(store ClientStore, out io.Writer) int {
	summaries, err := store.List()
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	if len(summaries) == 0 {
		fmt.Fprintln(out, "no clients registered")
		return 0
	}

	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "CLIENT ID\tNAME\tROLE\tCREATED\tSTATUS")
	for _, summary := range summaries {
		status := "active"
		if summary.Revoked {
			status = "revoked"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			summary.ClientID, summary.Name, summary.Role,
			summary.CreatedAt.UTC().Format(time.RFC3339), status)
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	return 0
}

func clientsRotate(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients rotate", flag.ContinueOnError)
	flags.SetOutput(out)
	clientID := flags.String("id", "", "client id to rotate (required)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*clientID) == "" {
		fmt.Fprintln(out, "error: --id is required")
		return 2
	}

	token, err := store.Rotate(*clientID)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "token: %s\n", token)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "The previous token stopped working the moment this one was issued.")
	fmt.Fprintln(out, "Update the client's configuration and restart it now.")

	return 0
}

func clientsRevoke(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients revoke", flag.ContinueOnError)
	flags.SetOutput(out)
	clientID := flags.String("id", "", "client id to revoke (required)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*clientID) == "" {
		fmt.Fprintln(out, "error: --id is required")
		return 2
	}

	if err := store.Revoke(*clientID); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "revoked %s\n", *clientID)
	fmt.Fprintln(out, "Entries it already wrote keep its attribution.")

	return 0
}

// runClientsCommand wires the CLI to a real registry. It never starts a
// listener.
func runClientsCommand(args []string) int {
	cfg := loadConfig()
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		fmt.Fprintln(os.Stderr, "error: DATABASE_URL is required")
		return 1
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open database: %v\n", err)
		return 1
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to reach database: %v\n", err)
		return 1
	}

	store, err := NewPostgresClientStore(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open client registry: %v\n", err)
		return 1
	}

	return runClientsCLI(store, args, os.Stdout)
}
