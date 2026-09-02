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

// clientsHandler is the shape shared by every subcommand. clientsList takes
// no flags of its own, so it is wrapped below to fit the same signature.
type clientsHandler func(store ClientStore, args []string, out io.Writer) int

// clientsHandlers is the single source of truth for which subcommands exist.
// runClientsCLI dispatches from it and runClientsCommand validates against it
// before touching the database, so a fifth subcommand added here cannot be
// forgotten in the other.
var clientsHandlers = map[string]clientsHandler{
	"register": clientsRegister,
	"list": func(store ClientStore, args []string, out io.Writer) int {
		return clientsList(store, out)
	},
	"rotate": clientsRotate,
	"revoke": clientsRevoke,
}

// isClientsCommand reports whether name is a known clients subcommand.
func isClientsCommand(name string) bool {
	_, ok := clientsHandlers[name]
	return ok
}

// runClientsCLI executes an admin subcommand against a registry. It takes the
// store and the output stream as arguments so it is testable without a
// database. The return value is the process exit code.
func runClientsCLI(store ClientStore, args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, clientsUsage)
		return 2
	}

	handler, ok := clientsHandlers[args[0]]
	if !ok {
		fmt.Fprintf(out, "unknown command %q\n\n%s\n", args[0], clientsUsage)
		return 2
	}

	return handler(store, args[1:], out)
}

func clientsRegister(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients register", flag.ContinueOnError)
	flags.SetOutput(out)
	name := flags.String("name", "", "human-readable client name (required)")
	role := flags.String("role", RoleClient, "client or admin")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(out, "error: --name is required")
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
	fmt.Fprintln(out, "This token is not recoverable: only its hash is stored. Save it now.")
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
// listener. Usage errors (no subcommand, an unknown one) are detected
// against clientsHandlers before loadConfig or any database call, so a
// mistyped command reports exit 2 whether or not DATABASE_URL is set or the
// database is reachable — the two are not the same failure and a deployment
// script needs to tell them apart.
func runClientsCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stdout, clientsUsage)
		return 2
	}
	if !isClientsCommand(args[0]) {
		fmt.Fprintf(os.Stdout, "unknown command %q\n\n%s\n", args[0], clientsUsage)
		return 2
	}

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
