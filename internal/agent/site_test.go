package agent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
)

var cpFiles = map[string]string{"cp-noise.yaml": "processors:\n  filter/noise:\n    error_mode: ignore\n"}

// v0.23.0: an overlay set is handed to root once per revision, root's result reported once; an update in the same
// document goes first and the set follows with the next document.
func TestSiteRequestHandedOnce(t *testing.T) {
	cp, pre, f := startAgent(t, "  update:\n    allow: true\n  site:\n    allow: true\n", "v0.23.0")
	rev := cp.PublishSite("app-1", dbProbe, 3, cpFiles, nil)
	s := waitStatuses(t, cp, 1)[0]
	if s.Result != "applied" || s.Revision != rev || s.Site == nil || s.Site.Result != "started" || s.Site.Revision != 3 || s.Update != nil {
		t.Fatalf("site status: %+v %+v", s, s.Site)
	}
	if f.count(startCmd) != 1 {
		t.Errorf("unit start: %q", f.calls)
	}
	raw, err := os.ReadFile(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile)))
	if err != nil {
		t.Fatal(err)
	}
	var d agent.Doc
	if err := json.Unmarshal(raw, &d); err != nil || d.Sig == "" || d.Site == nil || d.Site.Revision != 3 || d.Revision != rev {
		t.Errorf("request file is not the signed document: %v %s", err, raw)
	}
	// the same set revision again: not handed again
	cp.PublishSite("app-1", dbProbe, 3, cpFiles, nil)
	if s := waitStatuses(t, cp, 2)[1]; s.Site != nil {
		t.Errorf("repeated set: %+v", s.Site)
	}
	// root's result: reported once
	b, _ := json.Marshal(agent.SiteResult{Revision: 3, DocRevision: rev, Result: "ok", Detail: "applied", At: 1})
	if err := os.WriteFile(filepath.Join(pre, filepath.FromSlash(agent.SiteResultFile)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	s = waitStatuses(t, cp, 3)[2]
	if s.Site == nil || s.Site.Result != "ok" || s.Site.Revision != 3 {
		t.Fatalf("result status: %+v %+v", s, s.Site)
	}
	time.Sleep(800 * time.Millisecond)
	if n := len(cp.Statuses()); n != 3 {
		t.Errorf("the result was reported %d times", n-2)
	}
	// a new update and a new set in one document: the update goes first, the set with the next document
	cp.PublishSite("app-1", dbProbe, 4, cpFiles, map[string]any{"version": "v0.23.1", "id": "u-0123456789"})
	if s := waitStatuses(t, cp, 4)[3]; s.Update == nil || s.Update.Result != "started" || s.Site != nil {
		t.Fatalf("update first: %+v %+v %+v", s, s.Update, s.Site)
	}
	cp.PublishSite("app-1", dbProbe, 4, cpFiles, map[string]any{"version": "v0.23.1", "id": "u-0123456789"})
	if s := waitStatuses(t, cp, 5)[4]; s.Update != nil || s.Site == nil || s.Site.Revision != 4 || s.Site.Result != "started" {
		t.Fatalf("then the set: %+v %+v %+v", s, s.Update, s.Site)
	}
	if st, _ := agent.LoadState(pre); st.SiteRevision != 4 || st.SiteReported != 3 {
		t.Errorf("state: %+v", st)
	}
	invs, _ := cp.Inventories()
	if len(invs) == 0 || !invs[0].SiteAllowed {
		t.Errorf("inventory: site_allowed not true: %+v", invs)
	}
}

func TestSiteRequestRefusedByTheAgent(t *testing.T) {
	cases := []struct {
		name, policy string
		files        map[string]string
		want         string
	}{
		{"switch off (default)", "", cpFiles, "agent.site.allow"},
		{"outside the catalog", "  site:\n    allow: true\n", map[string]string{"cp-x.yaml": "receivers:\n  file_log: {}\n"}, "not allowed"},
		{"bad name", "  site:\n    allow: true\n", map[string]string{"10-x.yaml": "processors: {}\n"}, "overlay name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp, pre, f := startAgent(t, c.policy, "v0.23.0")
			cp.PublishSite("app-1", dbProbe, 1, c.files, nil)
			s := waitStatuses(t, cp, 1)[0]
			if s.Result != "applied" || s.Site == nil || s.Site.Result != "refused" || !strings.Contains(s.Site.Detail, c.want) {
				t.Fatalf("status: %+v %+v", s, s.Site)
			}
			if _, err := os.Stat(filepath.Join(pre, filepath.FromSlash(agent.UpdateRequestFile))); err == nil || f.count("systemctl start") != 0 {
				t.Error("a refused set was handed to root")
			}
		})
	}
}
