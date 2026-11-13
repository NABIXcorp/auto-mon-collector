package generate

import "testing"

func TestValidMirror(t *testing.T) {
	for _, ok := range []string{"", "https://console.example/agent/dl/", "https://10.0.0.1:8091/dl/"} {
		if err := ValidMirror(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://console.example/dl/", "https://console.example/dl", "https://u:p@x.example/dl/",
		"https://x.example/dl/?a=1", "ftp://x/", "https:///dl/", "https://x.example/d l/"} {
		if ValidMirror(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if (Answers{ReleaseMirror: "http://x/"}).Validate() == nil {
		t.Error("Validate accepted an http mirror")
	}
}
