package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"jenderalscan/internal/models"
)

func TestScopeLockBlocksExternalRedirect(t *testing.T) {
	externalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("EXTERNAL_HOST_REACHED"))
	}))
	defer externalSrv.Close()

	// Target server redirects to a different host (external.invalid)
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://external-out-of-scope.invalid/secret", http.StatusFound)
	}))
	defer targetSrv.Close()

	scope, err := ParseAndValidateTarget(targetSrv.URL, true)
	if err != nil {
		t.Fatalf("ParseAndValidateTarget: %v", err)
	}
	if scope.IsInScope("https://external-out-of-scope.invalid/secret") {
		t.Fatal("expected external domain to be out of scope")
	}

	client, err := NewScopedClient(scope, models.DefaultSettings())
	if err != nil {
		t.Fatalf("NewScopedClient: %v", err)
	}

	base, err := client.FetchBaseline(context.Background())
	if err != nil {
		t.Fatalf("FetchBaseline: %v", err)
	}
	if len(base.RedirectChain) != 0 {
		t.Fatalf("expected ScopeLock to prevent following out-of-scope redirect, got chain: %v", base.RedirectChain)
	}
}
