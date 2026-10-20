// Package dns manages the network's hostname record and the temporary TXT
// records used to prove domain ownership for the certificate.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"covee.io/cli/internal/prompt"
)

// Provider changes records in the domain's DNS.
type Provider interface {
	// Describe names the provider and zone for messages.
	Describe() string
	// CurrentA returns the IPv4 addresses the name has now (empty if none).
	CurrentA(ctx context.Context, name string) ([]string, error)
	// SetA points name at one IPv4 address.
	SetA(ctx context.Context, name, ip string) error
	// SetTXT adds a TXT value; RemoveTXT removes it again.
	SetTXT(ctx context.Context, name, value string) error
	RemoveTXT(ctx context.Context, name, value string) error
}

// Route53API is the part of the Route 53 client this package uses.
type Route53API interface {
	ListHostedZonesByName(context.Context, *route53.ListHostedZonesByNameInput, ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	GetChange(context.Context, *route53.GetChangeInput, ...func(*route53.Options)) (*route53.GetChangeOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// Route53 manages records in one public hosted zone.
type Route53 struct {
	API    Route53API
	ZoneID string
	Zone   string // without the trailing dot
	// Poll is how often to check that a change reached every name server.
	Poll time.Duration
}

// FindZone finds the most specific public hosted zone containing host.
func FindZone(ctx context.Context, api Route53API, host string) (*Route53, error) {
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".") + "."
		out, err := api.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{DNSName: aws.String(candidate), MaxItems: aws.Int32(10)})
		if err != nil {
			return nil, fmt.Errorf("listing Route 53 zones: %w", err)
		}
		for _, z := range out.HostedZones {
			if aws.ToString(z.Name) == candidate && (z.Config == nil || !z.Config.PrivateZone) {
				return &Route53{API: api, ZoneID: strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/"), Zone: strings.TrimSuffix(candidate, "."), Poll: 5 * time.Second}, nil
			}
		}
	}
	return nil, fmt.Errorf("no public Route 53 hosted zone contains %s in this AWS account", host)
}

func (r *Route53) Describe() string { return fmt.Sprintf("Route 53 zone %s (%s)", r.Zone, r.ZoneID) }

func fqdn(name string) string { return strings.TrimSuffix(name, ".") + "." }

func (r *Route53) records(ctx context.Context, name string, kind types.RRType) ([]string, error) {
	out, err := r.API.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(r.ZoneID), StartRecordName: aws.String(fqdn(name)), StartRecordType: kind, MaxItems: aws.Int32(1)})
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	var values []string
	for _, set := range out.ResourceRecordSets {
		if !strings.EqualFold(aws.ToString(set.Name), fqdn(name)) || set.Type != kind {
			continue
		}
		for _, rr := range set.ResourceRecords {
			values = append(values, aws.ToString(rr.Value))
		}
	}
	return values, nil
}

func (r *Route53) CurrentA(ctx context.Context, name string) ([]string, error) {
	return r.records(ctx, name, types.RRTypeA)
}

func (r *Route53) change(ctx context.Context, action types.ChangeAction, name string, kind types.RRType, ttl int64, values []string) error {
	var rrs []types.ResourceRecord
	for _, v := range values {
		rrs = append(rrs, types.ResourceRecord{Value: aws.String(v)})
	}
	out, err := r.API.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(r.ZoneID),
		ChangeBatch: &types.ChangeBatch{
			Comment: aws.String("covee"),
			Changes: []types.Change{{Action: action, ResourceRecordSet: &types.ResourceRecordSet{
				Name: aws.String(fqdn(name)), Type: kind, TTL: aws.Int64(ttl), ResourceRecords: rrs}}},
		},
	})
	if err != nil {
		return fmt.Errorf("changing %s: %w", name, err)
	}
	id := out.ChangeInfo.Id
	deadline := time.Now().Add(5 * time.Minute)
	for {
		got, err := r.API.GetChange(ctx, &route53.GetChangeInput{Id: id})
		if err != nil {
			return fmt.Errorf("waiting for %s: %w", name, err)
		}
		if got.ChangeInfo.Status == types.ChangeStatusInsync {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("Route 53 did not finish changing %s within 5 minutes", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.Poll):
		}
	}
}

func (r *Route53) SetA(ctx context.Context, name, ip string) error {
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("%q is not an IPv4 address", ip)
	}
	return r.change(ctx, types.ChangeActionUpsert, name, types.RRTypeA, 300, []string{ip})
}

// RemoveA deletes name's A record. A name without one is not an error.
func (r *Route53) RemoveA(ctx context.Context, name string) error {
	out, err := r.API.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(r.ZoneID), StartRecordName: aws.String(fqdn(name)), StartRecordType: types.RRTypeA, MaxItems: aws.Int32(1)})
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	for _, set := range out.ResourceRecordSets {
		if !strings.EqualFold(aws.ToString(set.Name), fqdn(name)) || set.Type != types.RRTypeA || set.AliasTarget != nil {
			continue
		}
		// Route 53 deletes a record only when given exactly what it holds.
		var values []string
		for _, rr := range set.ResourceRecords {
			values = append(values, aws.ToString(rr.Value))
		}
		return r.change(ctx, types.ChangeActionDelete, name, types.RRTypeA, aws.ToInt64(set.TTL), values)
	}
	return nil
}

func quote(v string) string { return `"` + v + `"` }

// SetTXT adds value to name's TXT record, keeping any values already there.
func (r *Route53) SetTXT(ctx context.Context, name, value string) error {
	existing, err := r.records(ctx, name, types.RRTypeTxt)
	if err != nil {
		return err
	}
	for _, v := range existing {
		if v == quote(value) {
			return nil
		}
	}
	return r.change(ctx, types.ChangeActionUpsert, name, types.RRTypeTxt, 60, append(existing, quote(value)))
}

// RemoveTXT removes value from name's TXT record, keeping any other values.
func (r *Route53) RemoveTXT(ctx context.Context, name, value string) error {
	existing, err := r.records(ctx, name, types.RRTypeTxt)
	if err != nil {
		return err
	}
	var keep []string
	found := false
	for _, v := range existing {
		if v == quote(value) {
			found = true
			continue
		}
		keep = append(keep, v)
	}
	if !found {
		return nil
	}
	if len(keep) == 0 {
		return r.change(ctx, types.ChangeActionDelete, name, types.RRTypeTxt, 60, existing)
	}
	return r.change(ctx, types.ChangeActionUpsert, name, types.RRTypeTxt, 60, keep)
}

// Manual asks the person to make each change at their DNS host and waits
// until public DNS shows it.
type Manual struct {
	Ask      prompt.Asker
	Resolver *net.Resolver
	Poll     time.Duration
	Timeout  time.Duration
}

func (m *Manual) Describe() string { return "your DNS host (changed by hand)" }

func (m *Manual) resolver() *net.Resolver {
	if m.Resolver != nil {
		return m.Resolver
	}
	return net.DefaultResolver
}

func (m *Manual) CurrentA(ctx context.Context, name string) ([]string, error) {
	addrs, err := m.resolver().LookupIP(ctx, "ip4", name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out, nil
}

func (m *Manual) wait(ctx context.Context, what string, ok func() bool) error {
	timeout, poll := m.Timeout, m.Poll
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	if poll == 0 {
		poll = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not appear in public DNS within %s", what, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
	return nil
}

func (m *Manual) SetA(ctx context.Context, name, ip string) error {
	m.Ask.Say("  At your DNS host, create or change this record:\n    %s  A  %s  (TTL 300)", name, ip)
	if ok, err := m.Ask.Confirm("dns_a_done", "Done", true); err != nil || !ok {
		return orAborted(err)
	}
	m.Ask.Say("  Waiting until %s resolves to %s...", name, ip)
	return m.wait(ctx, "The A record", func() bool {
		got, _ := m.CurrentA(ctx, name)
		return len(got) == 1 && got[0] == ip
	})
}

func (m *Manual) SetTXT(ctx context.Context, name, value string) error {
	m.Ask.Say("  At your DNS host, add this TXT record (it can be removed after setup):\n    %s  TXT  %s", name, value)
	if ok, err := m.Ask.Confirm("dns_txt_done", "Done", true); err != nil || !ok {
		return orAborted(err)
	}
	m.Ask.Say("  Waiting until the TXT record is visible...")
	return m.wait(ctx, "The TXT record", func() bool {
		values, _ := m.resolver().LookupTXT(ctx, name)
		for _, v := range values {
			if v == value {
				return true
			}
		}
		return false
	})
}

func (m *Manual) RemoveTXT(ctx context.Context, name, value string) error {
	m.Ask.Say("  You can now delete the TXT record %s.", name)
	return nil
}

func orAborted(err error) error {
	if err != nil {
		return err
	}
	return prompt.ErrAborted
}
