package mcpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverVersion = "0.3.0"

const maxMCPRequestBytes = 1 << 20

type rateWindow struct {
	start time.Time
	count int
}

type mcpRateLimiter struct {
	mu      sync.Mutex
	clients map[string]rateWindow
}

// NewHandler Create MCP HTTP handler, Mount to Main Route
// deps Yes. MCP Internal service dependency for tools
// apiKey For management level API Key; Deny all requests in time
func NewHandler(deps *Deps, apiKey string) http.Handler {
	if strings.TrimSpace(apiKey) == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "MCP is unavailable: API key is not configured", http.StatusServiceUnavailable)
		})
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "argus",
		Version: serverVersion,
	}, &mcp.ServerOptions{
		Instructions: "Argus is a web app and external pen testing framework for authorized security research. Use the global asset inventory, clustered hunting leads, evidence workspace, and scope-controlled PoC validation workflow. Confirm authorization scope before scans or PoC requests access external targets.",
	})

	RegisterTools(server, deps)

	h := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return server },
		nil,
	)

	limiter := &mcpRateLimiter{clients: make(map[string]rateWindow)}
	return limiter.middleware(mcpAuthMiddleware(h, apiKey))
}

// mcpAuthMiddleware MCP Authenticate intermediates
// Support two modes of transmission API Key:
//   - Authorization: Bearer <key>
//   - X-API-Key: <key>
func mcpAuthMiddleware(next http.Handler, apiKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxMCPRequestBytes)
		if !checkAPIKey(r, apiKey) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized: invalid or missing API key"},"id":null}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func checkAPIKey(r *http.Request, expected string) bool {
	// Authorization: Bearer <key>
	if auth := r.Header.Get("Authorization"); auth != "" {
		if key, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return secureEqual(strings.TrimSpace(key), expected)
		}
	}
	// X-API-Key: <key>
	if key := r.Header.Get("X-API-Key"); key != "" {
		return secureEqual(strings.TrimSpace(key), expected)
	}
	return false
}

func secureEqual(actual, expected string) bool {
	actualHash := sha256.Sum256([]byte(actual))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(actualHash[:], expectedHash[:]) == 1
}

func (l *mcpRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		now := time.Now()
		l.mu.Lock()
		if len(l.clients) >= 10000 {
			for client, value := range l.clients {
				if now.Sub(value.start) >= time.Minute {
					delete(l.clients, client)
				}
			}
		}
		if _, exists := l.clients[host]; !exists && len(l.clients) >= 10000 {
			l.mu.Unlock()
			http.Error(w, "rate limiter capacity exceeded", http.StatusServiceUnavailable)
			return
		}
		window := l.clients[host]
		if window.start.IsZero() || now.Sub(window.start) >= time.Minute {
			window = rateWindow{start: now}
		}
		window.count++
		l.clients[host] = window
		allowed := window.count <= 120
		l.mu.Unlock()
		if !allowed {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
