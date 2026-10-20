package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CloudflareAPI is Cloudflare's API address.
const CloudflareAPI = "https://api.cloudflare.com/client/v4"

// Cloudflare manages records in one Cloudflare zone with an API token that may
// edit the zone's DNS. Records it did not make are changed only when they
// differ from what is wanted, so a record kept by other tools (such as
// OpenTofu) stays as it is when it already points at the right address.
type Cloudflare struct {
	Base   string // CloudflareAPI when empty
	HTTP   *http.Client
	Token  func(context.Context) (string, error)
	ZoneID string
	Zone   string
	// Lookup asks one of the zone's name servers for a name's TXT values, to
	// wait until a change is live there; nil asks it over DNS.
	Lookup  func(ctx context.Context, server, name string) ([]string, error)
	Poll    time.Duration
	Timeout time.Duration

	servers []string
}

// CloudflareError is an unsuccessful Cloudflare API answer.
type CloudflareError struct {
	Status   int
	Messages []string
}

func (e *CloudflareError) Error() string {
	msg := strings.Join(e.Messages, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		return fmt.Sprintf("Cloudflare refused the token (HTTP %d: %s); it needs Zone → DNS → Edit for the zone", e.Status, msg)
	}
	return fmt.Sprintf("Cloudflare HTTP %d: %s", e.Status, msg)
}

type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied *bool  `json:"proxied,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	if c.Token == nil {
		return fmt.Errorf("no Cloudflare token")
	}
	token, err := c.Token(ctx)
	if err != nil {
		return err
	}
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(data)
	}
	base := c.Base
	if base == "" {
		base = CloudflareAPI
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("reaching Cloudflare: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var answer struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &answer); err != nil || resp.StatusCode >= 300 || !answer.Success {
		e := &CloudflareError{Status: resp.StatusCode}
		for _, m := range answer.Errors {
			e.Messages = append(e.Messages, fmt.Sprintf("%s (%d)", m.Message, m.Code))
		}
		return e
	}
	if out != nil && len(answer.Result) > 0 {
		return json.Unmarshal(answer.Result, out)
	}
	return nil
}

type cfZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
}

// FindCloudflareZone finds the most specific active zone containing host that
// the token can see. c supplies the token and API address.
func FindCloudflareZone(ctx context.Context, c *Cloudflare, host string) (*Cloudflare, error) {
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var zones []cfZone
		if err := c.do(ctx, "GET", "/zones?status=active&name="+url.QueryEscape(candidate), nil, &zones); err != nil {
			return nil, fmt.Errorf("looking for the Cloudflare zone of %s: %w", host, err)
		}
		for _, z := range zones {
			if strings.EqualFold(z.Name, candidate) {
				found := *c
				found.ZoneID, found.Zone, found.servers = z.ID, z.Name, z.NameServers
				return &found, nil
			}
		}
	}
	return nil, fmt.Errorf("the Cloudflare token cannot see a zone containing %s; give it Zone → DNS → Edit for that zone", host)
}

func (c *Cloudflare) Describe() string {
	return fmt.Sprintf("Cloudflare zone %s (%s)", c.Zone, c.ZoneID)
}

func (c *Cloudflare) records(ctx context.Context, name, kind string) ([]cfRecord, error) {
	name = strings.TrimSuffix(name, ".")
	var found []cfRecord
	q := url.Values{"type": {kind}, "name": {name}, "per_page": {"100"}}
	if err := c.do(ctx, "GET", "/zones/"+url.PathEscape(c.ZoneID)+"/dns_records?"+q.Encode(), nil, &found); err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	var out []cfRecord
	for _, r := range found {
		if strings.EqualFold(r.Name, name) && r.Type == kind {
			out = append(out, r)
		}
	}
	return out, nil
}

func (c *Cloudflare) CurrentA(ctx context.Context, name string) ([]string, error) {
	records, err := c.records(ctx, name, "A")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range records {
		out = append(out, r.Content)
	}
	sort.Strings(out)
	return out, nil
}

func (c *Cloudflare) recordPath(id string) string {
	return "/zones/" + url.PathEscape(c.ZoneID) + "/dns_records/" + url.PathEscape(id)
}

// SetA points name at ip, answered by DNS only: Cloudflare's proxy cannot
// carry the coordinator's connections or UDP 3478.
func (c *Cloudflare) SetA(ctx context.Context, name, ip string) error {
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("%q is not an IPv4 address", ip)
	}
	existing, err := c.records(ctx, name, "A")
	if err != nil {
		return err
	}
	off := false
	if len(existing) == 1 && existing[0].Content == ip && existing[0].Proxied != nil && !*existing[0].Proxied {
		return nil
	}
	if len(existing) == 0 {
		rec := cfRecord{Type: "A", Name: strings.TrimSuffix(name, "."), Content: ip, TTL: 300, Proxied: &off, Comment: "covee"}
		if err := c.do(ctx, "POST", "/zones/"+url.PathEscape(c.ZoneID)+"/dns_records", rec, nil); err != nil {
			return fmt.Errorf("creating %s: %w", name, err)
		}
		return nil
	}
	if err := c.do(ctx, "PATCH", c.recordPath(existing[0].ID), map[string]any{"content": ip, "ttl": 300, "proxied": false}, nil); err != nil {
		return fmt.Errorf("changing %s: %w", name, err)
	}
	for _, extra := range existing[1:] {
		if err := c.do(ctx, "DELETE", c.recordPath(extra.ID), nil, nil); err != nil {
			return fmt.Errorf("removing another address of %s: %w", name, err)
		}
	}
	return nil
}

// RemoveA deletes name's A records. A name without one is not an error.
func (c *Cloudflare) RemoveA(ctx context.Context, name string) error {
	existing, err := c.records(ctx, name, "A")
	if err != nil {
		return err
	}
	for _, r := range existing {
		if err := c.do(ctx, "DELETE", c.recordPath(r.ID), nil, nil); err != nil {
			return fmt.Errorf("deleting %s: %w", name, err)
		}
	}
	return nil
}

func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

// SetTXT adds a TXT value next to any already there, and returns once every
// name server of the zone answers with it.
func (c *Cloudflare) SetTXT(ctx context.Context, name, value string) error {
	existing, err := c.records(ctx, name, "TXT")
	if err != nil {
		return err
	}
	have := false
	for _, r := range existing {
		have = have || unquote(r.Content) == value
	}
	if !have {
		rec := cfRecord{Type: "TXT", Name: strings.TrimSuffix(name, "."), Content: quote(value), TTL: 60, Comment: "covee: temporary certificate check"}
		if err := c.do(ctx, "POST", "/zones/"+url.PathEscape(c.ZoneID)+"/dns_records", rec, nil); err != nil {
			return fmt.Errorf("creating %s: %w", name, err)
		}
	}
	return c.waitVisible(ctx, name, value)
}

// RemoveTXT removes value from name's TXT records, keeping any other values.
func (c *Cloudflare) RemoveTXT(ctx context.Context, name, value string) error {
	existing, err := c.records(ctx, name, "TXT")
	if err != nil {
		return err
	}
	for _, r := range existing {
		if unquote(r.Content) != value {
			continue
		}
		if err := c.do(ctx, "DELETE", c.recordPath(r.ID), nil, nil); err != nil {
			return fmt.Errorf("deleting %s: %w", name, err)
		}
	}
	return nil
}

func (c *Cloudflare) nameServers(ctx context.Context) ([]string, error) {
	if c.servers == nil {
		var z cfZone
		if err := c.do(ctx, "GET", "/zones/"+url.PathEscape(c.ZoneID), nil, &z); err != nil {
			return nil, fmt.Errorf("reading the zone %s: %w", c.Zone, err)
		}
		c.servers = append([]string{}, z.NameServers...)
	}
	return c.servers, nil
}

func (c *Cloudflare) waitVisible(ctx context.Context, name, value string) error {
	servers, err := c.nameServers(ctx)
	if err != nil {
		return err
	}
	lookup := c.Lookup
	if lookup == nil {
		lookup = lookupTXTAt
	}
	timeout, poll := c.Timeout, c.Poll
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if poll == 0 {
		poll = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for _, server := range servers {
		for {
			values, _ := lookup(ctx, server, name)
			found := false
			for _, v := range values {
				found = found || v == value
			}
			if found {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("Cloudflare's name server %s did not answer with the new %s record within %s", server, name, timeout)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(poll):
			}
		}
	}
	return nil
}

// lookupTXTAt asks one name server directly, bypassing caches.
func lookupTXTAt(ctx context.Context, server, name string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, server)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("finding %s: %w", server, err)
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(addrs[0], "53"))
	}}
	return r.LookupTXT(ctx, fqdn(name))
}
