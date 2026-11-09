package management

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostsNodes is a coordinator with a person's device, an offline one, the
// network's own devices and nothing else.
func hostsNodes(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/node" {
		w.WriteHeader(404)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"nodes": []map[string]any{
		{"id": "1", "given_name": "mac-mini", "online": true, "tags": []string{}},
		{"id": "2", "given_name": "pi", "online": false, "tags": []string{"tag:server"}},
		{"id": "3", "given_name": "hosts", "online": true, "tags": []string{"tag:covee-hosts"}},
		{"id": "4", "given_name": "console", "online": true, "tags": []string{"tag:covee-console"}},
	}})
}

// hostsServer is a console for a network with hosts. answer stands in for the
// server's apply-console-hosts; nil leaves requests unanswered.
func hostsServer(t *testing.T, handler http.HandlerFunc, answer func(hostsRequest) hostsStatus) (*Server, string) {
	t.Helper()
	s := newTestServer(t, handler)
	dir := t.TempDir()
	file := filepath.Join(dir, "hosts.json")
	if err := os.WriteFile(file, []byte(`{"hosts": [
	  {"name": "grafana.mesh.test", "address": "100.64.0.7", "port": 8080, "path": "/a", "scheme": "http", "verify": true, "device": "mac-mini", "node_id": "1"},
	  {"name": "off.mesh.test", "address": "100.64.0.8", "port": 80, "path": "", "scheme": "https", "verify": false, "device": "pi", "node_id": "2"},
	  {"name": "moved.mesh.test", "address": "100.64.0.8", "port": 81, "path": "", "scheme": "http", "verify": true, "device": "old-name", "node_id": "2"},
	  {"name": "gone.mesh.test", "address": "100.64.0.9", "port": 82, "path": "", "scheme": "http", "verify": true, "device": "gone", "node_id": "99"}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	if err := os.WriteFile(filepath.Join(dir, "domain.json"), []byte(`{"domain": "mesh.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s.hosts, err = newHosts(Config{HostsDir: filepath.Join(dir, "requests"), HostsFile: file})
	if err != nil {
		t.Fatal(err)
	}
	s.hosts.wait = 3 * time.Second
	if answer != nil {
		done := make(chan struct{})
		t.Cleanup(func() { close(done) })
		go func() {
			request := filepath.Join(s.hosts.dir, "request.json")
			var last string
			for {
				select {
				case <-done:
					return
				case <-time.After(10 * time.Millisecond):
				}
				raw, err := os.ReadFile(request)
				var r hostsRequest
				if err != nil || json.Unmarshal(raw, &r) != nil || r.ID == last {
					continue
				}
				last = r.ID
				status := answer(r)
				status.ID = r.ID
				out, _ := json.Marshal(status)
				_ = writePrivateIfChanged(filepath.Join(s.hosts.dir, "status.json"), out)
			}
		}()
	}
	return s, file
}

type hostsPage struct {
	Enabled  bool         `json:"enabled"`
	Domain   string       `json:"domain"`
	Revision string       `json:"revision"`
	Hosts    []HostRow    `json:"hosts"`
	Devices  []HostDevice `json:"devices"`
	Device   *HostDevice  `json:"hostsDevice"`
	Problem  string       `json:"problem"`
	Warnings []string     `json:"warnings"`
}

func getHostsPage(t *testing.T, s *Server) hostsPage {
	t.Helper()
	w := request(s, "GET", "/api/hosts", "", bearer(), nil)
	assertStatus(t, w, 200)
	var page hostsPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func putHosts(s *Server, revision string, hosts ...HostInput) string {
	if hosts == nil {
		hosts = []HostInput{}
	}
	body, _ := json.Marshal(map[string]any{"hosts": hosts, "revision": revision})
	return string(body)
}

var grafana = HostInput{Name: "grafana", Device: "mac-mini", Port: 3000, Path: "/b", Scheme: "http", Verify: true}

func TestHostsPageWithoutHostsSaysSo(t *testing.T) {
	s := newTestServer(t, hostsNodes)
	w := request(s, "GET", "/api/hosts", "", bearer(), nil)
	assertStatus(t, w, 200)
	if strings.TrimSpace(w.Body.String()) != `{"enabled":false}` {
		t.Fatalf("view = %s", w.Body)
	}
	w = request(s, "PUT", "/api/hosts", `{"hosts":[],"revision":""}`, bearer(), nil)
	assertStatus(t, w, 404)
}

func TestHostsPageShowsHostsAndTheirDevices(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, nil)
	page := getHostsPage(t, s)
	if !page.Enabled || page.Domain != "mesh.test" || page.Revision == "" || page.Device == nil || !page.Device.Online {
		t.Fatalf("page = %+v", page)
	}
	want := map[string]string{"grafana": "online", "off": "offline", "moved": "renamed", "gone": "missing"}
	if len(page.Hosts) != len(want) {
		t.Fatalf("hosts = %+v", page.Hosts)
	}
	for _, h := range page.Hosts {
		if h.Status != want[h.Name] {
			t.Errorf("%s status = %s, want %s", h.Name, h.Status, want[h.Name])
		}
	}
	first := page.Hosts[0]
	if first.URL != "https://grafana.mesh.test" || first.Device != "mac-mini" || first.Port != 8080 || first.Path != "/a" || !first.Verify {
		t.Fatalf("first = %+v", first)
	}
	if page.Hosts[1].Scheme != "https" || page.Hosts[1].Verify {
		t.Fatalf("second = %+v", page.Hosts[1])
	}
	if len(page.Devices) != 2 || page.Devices[0].Name != "mac-mini" || page.Devices[1].Name != "pi" || page.Devices[1].Online {
		t.Fatalf("the network's own devices must not be offered: %+v", page.Devices)
	}
}

func TestHostsPageStillListsHostsWithoutTheCoordinator(t *testing.T) {
	s, _ := hostsServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, nil)
	page := getHostsPage(t, s)
	if len(page.Hosts) != 4 || page.Hosts[0].Status != "" || page.Problem == "" {
		t.Fatalf("page = %+v", page)
	}
}

func TestChangingHostsSendsTheListToTheServerAndReportsItsAnswer(t *testing.T) {
	var got hostsRequest
	s, _ := hostsServer(t, hostsNodes, func(r hostsRequest) hostsStatus {
		got = r
		return hostsStatus{OK: true, Warnings: []string{"careful"}}
	})
	page := getHostsPage(t, s)
	w := request(s, "PUT", "/api/hosts", putHosts(s, page.Revision, grafana), bearer(), nil)
	assertStatus(t, w, 200)
	var after hostsPage
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Warnings) != 1 || after.Warnings[0] != "careful" {
		t.Fatalf("after = %+v", after)
	}
	if got.Revision != page.Revision || len(got.Hosts) != 1 || got.Hosts[0] != grafana || got.Expires <= time.Now().Unix() {
		t.Fatalf("request = %+v", got)
	}
	info, err := os.Stat(filepath.Join(s.hosts.dir, "request.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("request.json: %v %v", info, err)
	}
	events := s.audit.latest()
	last := events[0]
	if last.Action != "hosts.update" || last.Outcome != "success" || !strings.Contains(last.Target, "grafana") {
		t.Fatalf("audit = %+v", events[:2])
	}
}

func TestTheServersRefusalReachesThePersonInItsOwnWords(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, func(hostsRequest) hostsStatus {
		return hostsStatus{Message: "No device named nope in this network"}
	})
	w := request(s, "PUT", "/api/hosts", putHosts(s, getHostsPage(t, s).Revision, grafana), bearer(), nil)
	assertStatus(t, w, 400)
	if !strings.Contains(w.Body.String(), "No device named nope in this network") {
		t.Fatalf("body = %s", w.Body)
	}
	if s.audit.latest()[0].Outcome != "failed" {
		t.Fatalf("audit = %+v", s.audit.latest()[0])
	}
}

func TestChangingHostsFromAnOldListIsRefused(t *testing.T) {
	s, file := hostsServer(t, hostsNodes, func(hostsRequest) hostsStatus { return hostsStatus{OK: true} })
	revision := getHostsPage(t, s).Revision
	// The command, or another admin, changed the list after the page loaded.
	if err := os.WriteFile(file, []byte(`{"hosts": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := request(s, "PUT", "/api/hosts", putHosts(s, revision, grafana), bearer(), nil)
	assertStatus(t, w, 409)
	if _, err := os.Stat(filepath.Join(s.hosts.dir, "request.json")); !os.IsNotExist(err) {
		t.Fatalf("a request was sent: %v", err)
	}
	// The server found the same at the last moment.
	s2, _ := hostsServer(t, hostsNodes, func(hostsRequest) hostsStatus { return hostsStatus{Conflict: true, Message: "changed"} })
	w = request(s2, "PUT", "/api/hosts", putHosts(s2, getHostsPage(t, s2).Revision, grafana), bearer(), nil)
	assertStatus(t, w, 409)
}

func TestAServerThatDoesNotAnswerIsReportedAsUncertain(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, nil)
	s.hosts.wait = 200 * time.Millisecond
	w := request(s, "PUT", "/api/hosts", putHosts(s, getHostsPage(t, s).Revision, grafana), bearer(), nil)
	assertStatus(t, w, 504)
	if !strings.Contains(w.Body.String(), "Refresh") {
		t.Fatalf("body = %s", w.Body)
	}
	if s.audit.latest()[0].Outcome != "uncertain" {
		t.Fatalf("audit = %+v", s.audit.latest()[0])
	}
}

func TestImpossibleHostsNeverReachTheServer(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, nil)
	rev := getHostsPage(t, s).Revision
	for name, bad := range map[string]HostInput{
		"dot in name":    {Name: "a.b", Device: "mac-mini", Port: 80, Scheme: "http", Verify: true},
		"upper case":     {Name: "Grafana", Device: "mac-mini", Port: 80, Scheme: "http", Verify: true},
		"no device":      {Name: "a", Port: 80, Scheme: "http", Verify: true},
		"device a path":  {Name: "a", Device: "../x", Port: 80, Scheme: "http", Verify: true},
		"port zero":      {Name: "a", Device: "mac-mini", Scheme: "http", Verify: true},
		"port too large": {Name: "a", Device: "mac-mini", Port: 70000, Scheme: "http", Verify: true},
		"other scheme":   {Name: "a", Device: "mac-mini", Port: 80, Scheme: "ftp", Verify: true},
		"long path":      {Name: "a", Device: "mac-mini", Port: 80, Path: "/" + strings.Repeat("a", 1024), Scheme: "http", Verify: true},
	} {
		w := request(s, "PUT", "/api/hosts", putHosts(s, rev, bad), bearer(), nil)
		if w.Code != 400 {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	w := request(s, "PUT", "/api/hosts", putHosts(s, rev, grafana, grafana), bearer(), nil)
	assertStatus(t, w, 400)
	if _, err := os.Stat(filepath.Join(s.hosts.dir, "request.json")); !os.IsNotExist(err) {
		t.Fatalf("a request was sent: %v", err)
	}
	w = request(s, "PUT", "/api/hosts", `{"hosts":[],"revision":"x","extra":1}`, bearer(), nil)
	assertStatus(t, w, 400)
}

func TestARequestWithoutAListIsRefused(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, func(hostsRequest) hostsStatus { return hostsStatus{OK: true} })
	rev := getHostsPage(t, s).Revision
	for _, body := range []string{`{"revision":"` + rev + `"}`, `{"hosts":null,"revision":"` + rev + `"}`} {
		assertStatus(t, request(s, "PUT", "/api/hosts", body, bearer(), nil), 400)
	}
	if _, err := os.Stat(filepath.Join(s.hosts.dir, "request.json")); !os.IsNotExist(err) {
		t.Fatalf("a request was sent: %v", err)
	}
	// An empty list is a real request: removing every host.
	assertStatus(t, request(s, "PUT", "/api/hosts", `{"hosts":[],"revision":"`+rev+`"}`, bearer(), nil), 200)
}

func TestAChangeThatWaitedForItsTurnIsNotMadeOnceNobodyIsWaiting(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, nil)
	s.hosts.wait = 100 * time.Millisecond
	s.hosts.turn <- struct{}{} // another change is going on
	defer func() { <-s.hosts.turn }()
	w := request(s, "PUT", "/api/hosts", putHosts(s, getHostsPage(t, s).Revision, grafana), bearer(), nil)
	assertStatus(t, w, 503)
	if _, err := os.Stat(filepath.Join(s.hosts.dir, "request.json")); !os.IsNotExist(err) {
		t.Fatalf("a request was sent: %v", err)
	}
}

func TestAnUnansweredRequestIsWrittenAgainForThePathUnit(t *testing.T) {
	s, _ := hostsServer(t, hostsNodes, nil)
	s.hosts.wait = hostsNudgeEvery + 500*time.Millisecond
	path := filepath.Join(s.hosts.dir, "request.json")
	seen := make(chan os.FileInfo, 8)
	go func() {
		var last os.FileInfo
		for i := 0; i < 100; i++ {
			time.Sleep(50 * time.Millisecond)
			info, err := os.Stat(path)
			if err == nil && (last == nil || !os.SameFile(last, info)) {
				last = info
				seen <- info
			}
		}
		close(seen)
	}()
	assertStatus(t, request(s, "PUT", "/api/hosts", putHosts(s, getHostsPage(t, s).Revision, grafana), bearer(), nil), 504)
	if first, second := <-seen, <-seen; first == nil || second == nil {
		t.Fatal("the request was written only once")
	}
}

func TestAnHTTPServiceAlwaysVerifies(t *testing.T) {
	out, err := cleanHosts([]HostInput{{Name: "a", Device: "b", Port: 1, Scheme: "http", Verify: false}})
	if err != nil || !out[0].Verify {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestChangedHostsNamesWhatChanged(t *testing.T) {
	a, b := HostInput{Name: "a", Port: 1}, HostInput{Name: "b", Port: 2}
	moved := b
	moved.Port = 3
	for _, c := range []struct {
		old, wanted []HostInput
		want        string
	}{
		{nil, []HostInput{a}, "hosts:a"},
		{[]HostInput{a, b}, []HostInput{a}, "hosts:b"},
		{[]HostInput{a, b}, []HostInput{a, moved}, "hosts:b"},
		{[]HostInput{a}, []HostInput{a}, "hosts"},
	} {
		if got := changedHosts(c.old, c.wanted); got != c.want {
			t.Errorf("changedHosts = %s, want %s", got, c.want)
		}
	}
}

func TestHostsSettingsGoTogether(t *testing.T) {
	base := Config{Listen: "127.0.0.1:8088", PublicURL: "http://127.0.0.1:8088", AdminToken: testToken, HeadscaleURL: "http://127.0.0.1:1", HeadscaleAPIKey: testAPIKey, DataDir: t.TempDir()}
	partial := base
	partial.HostsDir = "/data/hosts"
	if partial.validate() == nil {
		t.Fatal("hosts settings without a file were accepted")
	}
	relative := base
	relative.HostsDir, relative.HostsFile = "data", "/etc/hosts.json"
	if relative.validate() == nil {
		t.Fatal("a relative hosts path was accepted")
	}
}
