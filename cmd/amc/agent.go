package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/cloudprober"
	"github.com/NABIXcorp/auto-mon-collector/internal/engine"
	"github.com/NABIXcorp/auto-mon-collector/internal/version"
)

// agentStdin is replaced in tests.
var agentStdin io.Reader = os.Stdin

// agentCmd: `amc agent enrol --token-stdin` (root, once) and `amc agent run` (the unit monitoring-agent).
func agentCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "usage: amc agent enrol --token-stdin [--prefix DIR] | amc agent run [--prefix DIR]\n")
		return exitUsage
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("amc agent "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	prefix := fs.String("prefix", "/opt/monitoring", "")
	tokenStdin := fs.Bool("token-stdin", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch sub {
	case "run":
		_ = agent.Run(ctx, agent.Config{Prefix: *prefix, Run: runOutput,
			Versions: map[string]string{"amc": version.Version, "cloudprober": cloudprober.Version}})
		return exitOK
	case "enrol", "enroll":
		if !*tokenStdin {
			fmt.Fprintln(stderr, "amc agent enrol: give the one-time token on stdin with --token-stdin (never as an argument)")
			return exitUsage
		}
		if os.Geteuid() != 0 {
			fmt.Fprintln(stderr, "amc agent enrol: run as root (sudo): the key is written for the user "+engine.AgentUser)
			return exitUsage
		}
		u, err := user.Lookup(engine.AgentUser)
		if err != nil {
			fmt.Fprintf(stderr, "amc agent enrol: user %s missing: run `amc apply` with the agent section first\n", engine.AgentUser)
			return exitUsage
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		fmt.Fprint(stderr, "one-time enrolment token: ")
		tok, _ := bufio.NewReader(agentStdin).ReadString('\n')
		tok = strings.TrimSpace(tok)
		if tok == "" {
			fmt.Fprintln(stderr, "\namc agent enrol: no token")
			return exitUsage
		}
		if err := agent.Enrol(ctx, *prefix, "", tok, uid, gid, nil); err != nil {
			fmt.Fprintf(stderr, "\namc agent enrol: %v\n", err)
			return exitPlan
		}
		host, _ := os.Hostname()
		fmt.Fprintf(stdout, "\nenrolled as %s; the agent picks the key up within 15 s (journalctl -u monitoring-agent)\n", host)
		return exitOK
	default:
		fmt.Fprintf(stderr, "amc agent: unknown subcommand %q\n", sub)
		return exitUsage
	}
}

func runOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}
