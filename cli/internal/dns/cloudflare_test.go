package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCF is a tiny Cloudflare API with one account's zones.
type fakeCF struct {
	mu      sync.Mutex
	zones   []cfZone
	records []cfRecord
	next    int
	writes  []string // "METHOD path" of every change
}

func (f *fakeCF) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply := func(status int, result any) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": status < 300, "errors": []any{}, "result": result})
		}
		if r.Header.Get("Authorization") != "Bearer good-token" {
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": 9109, "message": "Unauthorized to access requested resource"}}})
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if r.Method != "GET" {
			f.writes = append(f.writes, r.Method+" "+r.URL.Path)
		}
		var body cfRecord
		var patch map[string]any
		if r.Method == "POST" {
			_ = json.NewDecoder(r.Body).Decode(&body)
		} else if r.Method == "PATCH" {
			_ = json.NewDecoder(r.Body).Decode(&patch)
		}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			var out []cfZone
			for _, z := range f.zones {
				if z.Name == r.URL.Query().Get("name") {
					out = append(out, z)
				}
			}
			reply(200, out)
		case r.Method == "GET" && len(parts) == 2:
			for _, z := range f.zones {
				if z.ID == parts[1] {
					reply(200, z)
					return
				}
			}
			reply(404, nil)
		case r.Method == "GET" && len(parts) == 3:
			out := []cfRecord{}
			for _, rec := range f.records {
				if rec.Type == r.URL.Query().Get("type") && rec.Name == r.URL.Query().Get("name") {
					out = append(out, rec)
				}
			}
			reply(200, out)
		case r.Method == "POST" && len(parts) == 3:
			f.next++
			body.ID = fmt.Sprintf("rec-%d", f.next)
			f.records = append(f.records, body)
			reply(200, body)
		case r.Method == "PATCH" && len(parts) == 4:
			for i := range f.records {
				if f.records[i].ID == parts[3] {
					if v, ok := patch["content"].(string); ok {
						f.records[i].Content = v
					}
					if v, ok := patch["proxied"].(bool); ok {
						f.records[i].Proxied = &v
					}
					reply(200, f.records[i])
					return
				}
			}
			reply(404, nil)
		case r.Method == "DELETE" && len(parts) == 4:
			for i := range f.records {
				if f.records[i].ID == parts[3] {
					f.records = append(f.records[:i], f.records[i+1:]...)
					reply(200, map[string]string{"id": parts[3]})
					return
				}
			}
			reply(404, nil)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			reply(500, nil)
		}
	})
}

func (f *fakeCF) add(rec cfRecord) {
	f.next++
	rec.ID = fmt.Sprintf("rec-%d", f.next)
	f.records = append(f.records, rec)
}

func newCloudflare(t *testing.T) (*fakeCF, *Cloudflare) {
	f := &fakeCF{zones: []cfZone{
		{ID: "zone-other", Name: "example.net", NameServers: []string{"x.ns.cloudflare.com"}},
		{ID: "zone-1", Name: "example.com", NameServers: []string{"ana.ns.cloudflare.com", "bart.ns.cloudflare.com"}},
	}}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return f, &Cloudflare{Base: srv.URL, Token: func(context.Context) (string, error) { return "good-token", nil }, Poll: time.Millisecond}
}

func TestFindCloudflareZoneChoosesTheZoneOfTheHost(t *testing.T) {
	ctx := context.Background()
	_, c := newCloudflare(t)
	z, err := FindCloudflareZone(ctx, c, "covee.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if z.ZoneID != "zone-1" || z.Zone != "example.com" || len(z.servers) != 2 || !strings.Contains(z.Describe(), "example.com") {
		t.Fatalf("got %+v", z)
	}
	if _, err := FindCloudflareZone(ctx, c, "vpn.example.org"); err == nil || !strings.Contains(err.Error(), "cannot see a zone") {
		t.Fatalf("found a zone the token cannot see: %v", err)
	}
	c.Token = func(context.Context) (string, error) { return "wrong", nil }
	if _, err := FindCloudflareZone(ctx, c, "covee.example.com"); err == nil || !strings.Contains(err.Error(), "Zone → DNS → Edit") {
		t.Fatalf("a refused token must say which permission it needs: %v", err)
	}
}

func TestCloudflareARecordKeepsAMatchingRecordAndFixesOthers(t *testing.T) {
	ctx := context.Background()
	f, c := newCloudflare(t)
	c.ZoneID, c.Zone = "zone-1", "example.com"
	host := "covee.example.com"
	off, on := false, true

	// A record kept by OpenTofu that already points at the server is left alone.
	f.add(cfRecord{Type: "A", Name: host, Content: "203.0.113.3", TTL: 300, Proxied: &off, Comment: "managed by infra-repo"})
	if err := c.SetA(ctx, host+".", "203.0.113.3"); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("a matching record must not be rewritten: %v", f.writes)
	}
	if got, _ := c.CurrentA(ctx, host); len(got) != 1 || got[0] != "203.0.113.3" {
		t.Fatalf("CurrentA = %v", got)
	}

	// A proxied record or a second address is corrected.
	f.records[0].Proxied = &on
	f.add(cfRecord{Type: "A", Name: host, Content: "198.51.100.7", TTL: 300, Proxied: &off})
	if err := c.SetA(ctx, host, "203.0.113.3"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || *f.records[0].Proxied || f.records[0].Content != "203.0.113.3" {
		t.Fatalf("records = %+v", f.records)
	}

	// A missing record is created, DNS only.
	if err := c.SetA(ctx, "other.example.com", "203.0.113.4"); err != nil {
		t.Fatal(err)
	}
	created := f.records[len(f.records)-1]
	if created.Name != "other.example.com" || created.Proxied == nil || *created.Proxied || created.TTL != 300 {
		t.Fatalf("created %+v", created)
	}
	if err := c.SetA(ctx, host, "not-an-ip"); err == nil {
		t.Fatal("accepted a bad address")
	}
	if err := c.RemoveA(ctx, "other.example.com"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.CurrentA(ctx, "other.example.com"); len(got) != 0 {
		t.Fatalf("RemoveA left %v", got)
	}
}

func TestCloudflareTXTWaitsForEveryNameServer(t *testing.T) {
	ctx := context.Background()
	f, c := newCloudflare(t)
	c.ZoneID, c.Zone = "zone-1", "example.com"
	name := "_acme-challenge.covee.example.com"
	f.add(cfRecord{Type: "TXT", Name: name, Content: `"other"`, TTL: 60})
	asked := map[string]int{}
	c.Lookup = func(_ context.Context, server, got string) ([]string, error) {
		if got != name {
			t.Errorf("looked up %s", got)
		}
		asked[server]++
		if asked[server] < 3 {
			return []string{"other"}, nil // not there yet
		}
		return []string{"other", "token"}, nil
	}
	if err := c.SetTXT(ctx, name, "token"); err != nil {
		t.Fatal(err)
	}
	if asked["ana.ns.cloudflare.com"] != 3 || asked["bart.ns.cloudflare.com"] != 3 {
		t.Fatalf("did not wait at every name server: %v", asked)
	}
	if len(f.records) != 2 || f.records[1].Content != `"token"` || f.records[1].TTL != 60 {
		t.Fatalf("records = %+v", f.records)
	}
	if err := c.RemoveTXT(ctx, name, "token"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || f.records[0].Content != `"other"` {
		t.Fatalf("other TXT values must stay: %+v", f.records)
	}

	c.Timeout = 10 * time.Millisecond
	c.Lookup = func(context.Context, string, string) ([]string, error) { return nil, nil }
	if err := c.SetTXT(ctx, name, "late"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("a record that never appears must time out: %v", err)
	}
}
