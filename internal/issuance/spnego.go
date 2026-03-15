package issuance

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"go.uber.org/zap"
)

type contextKey string

const (
	contextKeyPrincipal contextKey = "principal"
	contextKeyRealm     contextKey = "realm"
)

// Authenticator validates SPNEGO tokens and extracts the principal.
// Implementations are swapped for testing.
type Authenticator interface {
	Authenticate(r *http.Request) (principal string, realm string, err error)
}

// SPNEGOMiddleware returns HTTP middleware that validates SPNEGO tokens
// using the Authenticator interface and injects the authenticated principal
// into the request context. Used for testing with MockAuthenticator.
func SPNEGOMiddleware(auth Authenticator, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Negotiate") {
				w.Header().Set("WWW-Authenticate", "Negotiate")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			principal, realm, err := auth.Authenticate(r)
			if err != nil {
				logger.Warn("SPNEGO authentication failed",
					zap.String("remote_addr", r.RemoteAddr),
					zap.Error(err),
				)
				w.Header().Set("WWW-Authenticate", "Negotiate")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			logger.Debug("SPNEGO authentication successful",
				zap.String("principal", principal),
				zap.String("realm", realm),
			)

			ctx := context.WithValue(r.Context(), contextKeyPrincipal, principal)
			ctx = context.WithValue(ctx, contextKeyRealm, realm)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewKeytabMiddleware creates HTTP middleware that uses gokrb5's SPNEGOKRB5Authenticate
// for Kerberos authentication, then extracts the principal into the request context.
func NewKeytabMiddleware(kt *keytab.Keytab, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// The inner handler extracts the goidentity.Identity set by gokrb5
		// and injects principal/realm into our own context keys.
		extractor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := goidentity.FromHTTPRequestContext(r)
			if identity == nil {
				logger.Warn("no identity in context after SPNEGO validation",
					zap.String("remote_addr", r.RemoteAddr),
				)
				w.Header().Set("WWW-Authenticate", "Negotiate")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			principal := identity.UserName() + "@" + identity.Domain()
			realm := identity.Domain()

			logger.Debug("SPNEGO authentication successful",
				zap.String("principal", principal),
				zap.String("realm", realm),
			)

			ctx := context.WithValue(r.Context(), contextKeyPrincipal, principal)
			ctx = context.WithValue(ctx, contextKeyRealm, realm)
			next.ServeHTTP(w, r.WithContext(ctx))
		})

		// Wrap with gokrb5's SPNEGO handler
		// DecodePAC(false) skips PAC checksum verification which fails with
		// FreeIPA due to unsupported checksum algorithms in gokrb5.
		l := log.New(os.Stderr, "GOKRB5: ", log.LstdFlags)
		return spnego.SPNEGOKRB5Authenticate(extractor, kt, service.Logger(l), service.DecodePAC(false))
	}
}

// PrincipalFromContext returns the authenticated Kerberos principal from the request context.
func PrincipalFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeyPrincipal).(string)
	return v
}

// RealmFromContext returns the Kerberos realm from the request context.
func RealmFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeyRealm).(string)
	return v
}

// LoadKeytab loads a Kerberos keytab file from disk.
func LoadKeytab(path string) (*keytab.Keytab, error) {
	return keytab.Load(path)
}
