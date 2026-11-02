package generate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// v0.16.0: agent.update in answers.yaml: off by default, strict window syntax, kept by Marshal (update writes it back).
func TestAgentUpdateAnswers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "answers.yaml")
	write := func(s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base := "agent:\n  url: https://agent.example.com/agent/\n  control_plane_key: \"" + testKey + "\"\n"
	write(base)
	a, err := LoadAnswers(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Agent.Update.Allow || a.Agent.Update.Downgrade || a.Agent.Update.Window != "" {
		t.Errorf("defaults: %+v", a.Agent.Update)
	}
	write(base + "  update:\n    allow: true\n    window: \"22:00-04:00\"\n")
	if a, err = LoadAnswers(p); err != nil || !a.Agent.Update.Allow || a.Agent.Update.Window != "22:00-04:00" {
		t.Fatalf("%+v %v", a.Agent, err)
	}
	b, err := a.Marshal()
	if err != nil || !strings.Contains(string(b), "\n  update:\n    allow: true\n    window: 22:00-04:00\n") {
		t.Errorf("Marshal lost agent.update:\n%s", b)
	}
	for _, bad := range []string{"window: \"1:00-05:00\"", "window: \"01:00-01:00\"", "window: \"24:00-01:00\"",
		"window: \"01:00 - 05:00\"", "window: \"01:60-05:00\"", "allow: yes-please", "reboot: true"} {
		write(base + "  update:\n    " + bad + "\n")
		if _, err := LoadAnswers(p); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}

func TestAgentUpdatePolicy(t *testing.T) {
	on := AgentUpdate{Allow: true}
	cases := []struct {
		name            string
		u               AgentUpdate
		running, target string
		ok              bool
	}{
		{"off by default", AgentUpdate{}, "v0.16.0", "v0.16.1", false},
		{"newer", on, "v0.16.0", "v0.16.1", true},
		{"same", on, "v0.16.0", "v0.16.0", false},
		{"older", on, "v0.16.0", "v0.15.9", false},
		{"older with downgrade", AgentUpdate{Allow: true, Downgrade: true}, "v0.16.0", "v0.15.0", true},
		{"dev build, no downgrade", on, "dev", "v0.16.1", false},
		{"dev build, downgrade allowed", AgentUpdate{Allow: true, Downgrade: true}, "dev", "v0.16.1", true},
		{"bad target", on, "v0.16.0", "v0.17.0;rm", false},
		{"bad target with downgrade", AgentUpdate{Allow: true, Downgrade: true}, "v0.16.0", "latest", false},
	}
	for _, c := range cases {
		if err := c.u.Check(c.running, c.target); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestAgentUpdateWindow(t *testing.T) {
	at := func(hm string) time.Time {
		tm, err := time.ParseInLocation("15:04", hm, time.Local)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	for _, c := range []struct {
		window, now string
		in          bool
	}{
		{"", "13:37", true},
		{"01:00-05:00", "00:59", false}, {"01:00-05:00", "01:00", true}, {"01:00-05:00", "04:59", true},
		{"01:00-05:00", "05:00", false},
		// over midnight
		{"22:00-04:00", "21:59", false}, {"22:00-04:00", "22:00", true}, {"22:00-04:00", "23:59", true},
		{"22:00-04:00", "00:00", true}, {"22:00-04:00", "03:59", true}, {"22:00-04:00", "04:00", false},
		{"22:00-04:00", "12:00", false},
	} {
		err := AgentUpdate{Allow: true, Window: c.window}.InWindow(at(c.now))
		if (err == nil) != c.in {
			t.Errorf("window %q at %s: in=%v, err=%v", c.window, c.now, c.in, err)
		}
		if err != nil && !strings.Contains(err.Error(), "outside the update window") {
			t.Errorf("unclear reason: %v", err)
		}
	}
}
