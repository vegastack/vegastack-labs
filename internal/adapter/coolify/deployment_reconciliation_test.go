package coolify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObserveBoundDeploymentReadOnlyAndExact(t *testing.T) {
	for _, mode := range []string{"good", "wrong-server", "wrong-destination", "not-finished", "wrong-receipt", "missing-created", "fanout", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			fs := fixtures()
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" {
					t.Fatalf("reconciliation wrote %s", r.Method)
				}
				switch r.URL.Path {
				case "/api/v1/applications/app-one/destinations":
					body := `[{"uuid":"destination-one","server_id":5,"is_primary":true}]`
					if mode == "fanout" {
						body = `[{"server_id":5,"is_primary":true},{"server_id":6,"is_primary":false}]`
					}
					fmt.Fprint(w, body)
				case "/api/v1/deployments/applications/app-one":
					fmt.Fprint(w, `{"deployments":[{"deployment_uuid":"deployment-one"}]}`)
				case "/api/v1/deployments/deployment-one":
					body := `{"deployment_uuid":"deployment-one","status":"finished","server_id":5,"destination_id":"4","created_at":"2026-11-10T16:42:29.000000Z","logs":"never projected"}`
					switch mode {
					case "wrong-server":
						body = strings.Replace(body, `"server_id":5`, `"server_id":6`, 1)
					case "wrong-destination":
						body = strings.Replace(body, `"destination_id":"4"`, `"destination_id":"7"`, 1)
					case "not-finished":
						body = strings.Replace(body, `"finished"`, `"in_progress"`, 1)
					case "wrong-receipt":
						body = strings.Replace(body, `"deployment-one"`, `"other-one"`, 1)
					case "missing-created":
						body = strings.Replace(body, `"2026-11-10T16:42:29.000000Z"`, `""`, 1)
					}
					fmt.Fprint(w, body)
				default:
					body, ok := fs[r.URL.Path]
					if !ok {
						t.Fatalf("unexpected GET %s", r.URL.Path)
					}
					fmt.Fprint(w, body)
				}
			}))
			defer s.Close()
			c, e := NewClient(s.URL+"/api/v1", s.Client().Transport)
			if e != nil {
				t.Fatal(e)
			}
			checks := 0
			v := credential(t)
			out, e := c.ObserveBoundDeployment(context.Background(), target(), 5, "deployment-one", v, func() error {
				checks++
				if mode == "cancelled" {
					return ErrUnavailable
				}
				return nil
			})
			if mode == "good" {
				if e != nil || out.ProviderStatus != "finished" || out.CreatedAt != "2026-11-10T16:42:29Z" {
					t.Fatal(out, e)
				}
				if checks < calls {
					t.Fatal("missing current authority check")
				}
			} else if e == nil {
				t.Fatal("accepted", mode, out)
			}
			if mode == "cancelled" && calls != 0 {
				t.Fatal("request after cancelled authority")
			}
		})
	}
}
