// Command amc (auto-mon-collector) scans a Linux host, proposes what to monitor, generates the configuration
// for the official OpenTelemetry Collector (otelcol-contrib) and installs it on request. See docs/design.md.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

const usage = `auto-mon-collector (amc): host discovery installer for otelcol-contrib

Usage:
  amc plan        scan, propose, ask, generate, validate (read-only, default)
  amc apply       install what plan proposes (changes the system)
  amc detect      show what was found on this host
  amc sql <name>  print the database grants for a monitoring user
  amc uninstall   remove the installation
  amc version     show the version

Status: early development. Only "version" and "help" work yet (see docs/design.md, section 14).
`

// Exit codes (docs/design.md, section 8).
const (
	exitOK    = 0
	exitPlan  = 1
	exitUsage = 2
)

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "plan"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.String())
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "plan", "apply", "detect", "sql", "uninstall":
		fmt.Fprintf(stderr, "amc %s: not implemented yet (early development, see docs/design.md)\n", cmd)
		return exitPlan
	default:
		fmt.Fprintf(stderr, "amc: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
