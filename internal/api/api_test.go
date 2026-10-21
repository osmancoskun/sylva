package api_test

import (
	"net/http"
	"testing"

	"github.com/osman/sylva/internal/api"
)

func TestHTTPCatalogCoversPingRecordsAndSalt(t *testing.T) {
	seen := map[string]api.Endpoint{}
	for _, ep := range api.HTTPEndpoints() {
		if ep.Name == "" || ep.Method == "" || ep.Path == "" {
			t.Fatalf("incomplete endpoint: %+v", ep)
		}
		if _, dup := seen[ep.Name]; dup {
			t.Fatalf("duplicate endpoint name %q", ep.Name)
		}
		seen[ep.Name] = ep
	}

	prefix := "/api/v1"
	ping, ok := seen[api.EndpointPing]
	if !ok {
		t.Fatal("ping endpoint missing from catalog")
	}
	if got := ping.Pattern(prefix); got != http.MethodGet+" "+prefix+api.PathPing {
		t.Fatalf("ping pattern = %q", got)
	}

	healthz := seen[api.EndpointHealthz]
	if got := healthz.Pattern(prefix); got != http.MethodGet+" "+api.PathHealthz {
		t.Fatalf("healthz must be unprefixed, got %q", got)
	}

	if api.RecordPath("a/b") != "/records/a%2Fb" {
		t.Fatalf("record path escaping failed: %q", api.RecordPath("a/b"))
	}
	if api.RecordsQuery(api.QueryBlindIndex, "abc") != "/records?blind_index=abc" {
		t.Fatalf("records query = %q", api.RecordsQuery(api.QueryBlindIndex, "abc"))
	}
}

func TestAgentOpsCatalog(t *testing.T) {
	ops := api.AgentOps()
	if len(ops) == 0 {
		t.Fatal("agent op catalog is empty")
	}
	seen := map[string]bool{}
	for _, op := range ops {
		if op == "" {
			t.Fatal("empty agent op")
		}
		if seen[op] {
			t.Fatalf("duplicate agent op %q", op)
		}
		seen[op] = true
	}
	for _, want := range []string{
		api.AgentOpStatus,
		api.AgentOpUnlock,
		api.AgentOpLock,
		api.AgentOpMasterKey,
		api.AgentOpCopy,
		api.AgentOpScheduleClear,
	} {
		if !seen[want] {
			t.Fatalf("missing agent op %q", want)
		}
	}
}
