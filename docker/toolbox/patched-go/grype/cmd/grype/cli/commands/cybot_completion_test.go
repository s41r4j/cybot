package commands

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCybotMaintainedDockerCompletion(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/images/json") {
			t.Errorf("unexpected API route: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		var filters map[string]map[string]bool
		if json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters) != nil || !filters["dangling"]["false"] {
			t.Error("completion broadened its tagged-image filter")
		}
		w.Header().Set("Content-Type", "application/json")
		if fail.Load() {
			w.WriteHeader(500)
			w.Write([]byte(`{"message":"synthetic daemon failure"}`))
			return
		}
		w.Write([]byte(`[{"RepoTags":["cybot:fixture","other:latest"]}]`))
	}))
	defer server.Close()
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("DOCKER_API_VERSION", "1.55")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	tags, err := listLocalDockerImages("cybot")
	if err != nil || !reflect.DeepEqual(tags, []string{"cybot:fixture"}) {
		t.Fatalf("maintained client lost prefix matches: %v %v", tags, err)
	}
	tags, err = listLocalDockerImages("missing")
	if err != nil || len(tags) != 0 {
		t.Fatalf("completion invented a prefix match: %v %v", tags, err)
	}
	fail.Store(true)
	if _, err = listLocalDockerImages("cybot"); err == nil {
		t.Fatal("daemon failure became successful completion")
	}
	if calls.Load() != 3 {
		t.Fatalf("unexpected request count: %d", calls.Load())
	}
}
