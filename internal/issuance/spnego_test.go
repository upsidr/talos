package issuance

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// MockAuthenticator implements Authenticator for testing.
type MockAuthenticator struct {
	Principal string
	Realm     string
	Err       error
}

func (m *MockAuthenticator) Authenticate(r *http.Request) (string, string, error) {
	if m.Err != nil {
		return "", "", m.Err
	}
	return m.Principal, m.Realm, nil
}

func TestSPNEGOMiddleware_NoAuthHeader(t *testing.T) {
	auth := &MockAuthenticator{Principal: "user@REALM", Realm: "REALM"}
	logger := zap.NewNop()
	middleware := SPNEGOMiddleware(auth, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("POST", "/v1/issue", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Errorf("WWW-Authenticate = %q, want %q", got, "Negotiate")
	}
}

func TestSPNEGOMiddleware_InvalidToken(t *testing.T) {
	auth := &MockAuthenticator{Err: fmt.Errorf("invalid token")}
	logger := zap.NewNop()
	middleware := SPNEGOMiddleware(auth, logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest("POST", "/v1/issue", nil)
	req.Header.Set("Authorization", "Negotiate dGVzdHRva2Vu")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestSPNEGOMiddleware_ValidToken(t *testing.T) {
	auth := &MockAuthenticator{
		Principal: "johndoe@DIRECTORY.UPSIDR.LOCAL",
		Realm:     "DIRECTORY.UPSIDR.LOCAL",
	}
	logger := zap.NewNop()
	middleware := SPNEGOMiddleware(auth, logger)

	var gotPrincipal, gotRealm string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrincipal = PrincipalFromContext(r.Context())
		gotRealm = RealmFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/v1/issue", nil)
	req.Header.Set("Authorization", "Negotiate dGVzdHRva2Vu")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if gotPrincipal != "johndoe@DIRECTORY.UPSIDR.LOCAL" {
		t.Errorf("principal = %q, want %q", gotPrincipal, "johndoe@DIRECTORY.UPSIDR.LOCAL")
	}
	if gotRealm != "DIRECTORY.UPSIDR.LOCAL" {
		t.Errorf("realm = %q, want %q", gotRealm, "DIRECTORY.UPSIDR.LOCAL")
	}
}

func TestPrincipalFromContext_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := PrincipalFromContext(req.Context()); got != "" {
		t.Errorf("PrincipalFromContext = %q, want empty", got)
	}
}

func TestRealmFromContext_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := RealmFromContext(req.Context()); got != "" {
		t.Errorf("RealmFromContext = %q, want empty", got)
	}
}
