package app

import (
	"net"
	"net/http"
)

// localOnly guards the API against the web pages a rep has open in other
// tabs. There is no login (ADR-0005), so:
//   - the Host must name loopback, so a hostile domain re-pointed at
//     127.0.0.1 (DNS rebinding) can't read or drive Stackwell;
//   - a request that changes something must come from Stackwell's own page:
//     browsers always send Origin on a cross-site POST/PUT/DELETE, so a
//     foreign Origin is refused. Tools that send none (curl) still work.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "Stackwell only answers on its loopback address", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "requests from other websites are refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
