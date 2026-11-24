// Command fakecp runs the fake control plane for the CI end-to-end test (never released). It listens on 127.0.0.1,
// writes its public key to -key-out and takes test commands on /_test/*:
//
//	POST /_test/publish  {"host","revision","probes",...,"tamper","other_key","expires_at","site"|"disk_scan"|"rescan"|"services"}  -> {"revision"}
//	GET  /_test/status   reported statuses (JSON list)
//	GET  /_test/diskscans  disk scan results received (JSON list)
//	GET  /_test/inventories  inventories received (JSON list)
//	GET  /_test/enrolled?host=H   200 when enrolled
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/NABIXcorp/auto-mon-collector/internal/agent"
	"github.com/NABIXcorp/auto-mon-collector/internal/agent/agenttest"
	"github.com/NABIXcorp/auto-mon-collector/internal/generate"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18091", "")
	keyOut := flag.String("key-out", "", "file for the control-plane public key")
	flag.Parse()
	s := agenttest.New()
	if *keyOut != "" {
		if err := os.WriteFile(*keyOut, []byte(s.PublicKey()+"\n"), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/agent/", s)
	mux.HandleFunc("POST /_test/publish", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Host     string          `json:"host"`
			Revision int64           `json:"revision"`
			Probes   generate.Probes `json:"probes"`
			Expires  int64           `json:"expires_at"`
			Tamper   bool            `json:"tamper"`
			OtherKey bool            `json:"other_key"`
			// v0.23.0: an overlay set (the revision is then the next one)
			Site *agent.SiteRequest `json:"site"`
			// v0.29.0: a disk scan request
			DiskScan *agent.DiskScanRequest `json:"disk_scan"`
			// v0.32.0: a service re-scan request
			Rescan *agent.RescanRequest `json:"rescan"`
			// v0.33.0: service switches ({"revision","set"})
			Services *struct {
				Revision int64          `json:"revision"`
				Set      map[string]any `json:"set"`
			} `json:"services"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var rev int64
		if in.Services != nil {
			rev = s.PublishServices(in.Host, in.Probes, in.Services.Revision, in.Services.Set, nil)
		} else if in.Rescan != nil {
			rev = s.PublishRescan(in.Host, in.Probes, in.Rescan.ID)
		} else if in.DiskScan != nil {
			rev = s.PublishDiskScan(in.Host, in.Probes, in.DiskScan.ID)
		} else if in.Site != nil {
			rev = s.PublishSite(in.Host, in.Probes, in.Site.Revision, in.Site.Files, nil)
		} else {
			rev = s.Publish(in.Host, in.Revision, in.Probes, in.Expires, in.Tamper, in.OtherKey)
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"revision": rev})
	})
	mux.HandleFunc("GET /_test/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(s.Statuses())
	})
	// v0.29.0: the disk scan results received (a JSON list of the raw bodies)
	mux.HandleFunc("GET /_test/diskscans", func(w http.ResponseWriter, r *http.Request) {
		out := []json.RawMessage{}
		for _, b := range s.DiskScans() {
			out = append(out, b)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	// v0.32.0: the inventories received (rescan_allowed, services_at, the services)
	mux.HandleFunc("GET /_test/inventories", func(w http.ResponseWriter, r *http.Request) {
		invs, _ := s.Inventories()
		_ = json.NewEncoder(w).Encode(invs)
	})
	mux.HandleFunc("GET /_test/enrolled", func(w http.ResponseWriter, r *http.Request) {
		if !s.Enrolled(r.URL.Query().Get("host")) {
			http.NotFound(w, r)
		}
	})
	log.Printf("fakecp on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
