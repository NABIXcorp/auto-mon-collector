// Command fakecp runs the fake control plane for the CI end-to-end test (never released). It listens on 127.0.0.1,
// writes its public key to -key-out and takes test commands on /_test/*:
//
//	POST /_test/publish  {"host","revision","probes",...,"tamper","other_key","expires_at"}  -> {"revision"}
//	GET  /_test/status   reported statuses (JSON list)
//	GET  /_test/enrolled?host=H   200 when enrolled
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"

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
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rev := s.Publish(in.Host, in.Revision, in.Probes, in.Expires, in.Tamper, in.OtherKey)
		_ = json.NewEncoder(w).Encode(map[string]int64{"revision": rev})
	})
	mux.HandleFunc("GET /_test/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(s.Statuses())
	})
	mux.HandleFunc("GET /_test/enrolled", func(w http.ResponseWriter, r *http.Request) {
		if !s.Enrolled(r.URL.Query().Get("host")) {
			http.NotFound(w, r)
		}
	})
	log.Printf("fakecp on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
