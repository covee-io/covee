package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type fakeR53 struct {
	zones   []types.HostedZone
	records map[string][]string // "name|type" -> values
	changes []types.Change
	polls   int
}

func key(name string, t types.RRType) string { return strings.ToLower(name) + "|" + string(t) }

func (f *fakeR53) ListHostedZonesByName(_ context.Context, in *route53.ListHostedZonesByNameInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
	var out []types.HostedZone
	for _, z := range f.zones {
		if aws.ToString(z.Name) >= aws.ToString(in.DNSName) {
			out = append(out, z)
		}
	}
	return &route53.ListHostedZonesByNameOutput{HostedZones: out}, nil
}

func (f *fakeR53) ChangeResourceRecordSets(_ context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	for _, c := range in.ChangeBatch.Changes {
		f.changes = append(f.changes, c)
		k := key(aws.ToString(c.ResourceRecordSet.Name), c.ResourceRecordSet.Type)
		if c.Action == types.ChangeActionDelete {
			delete(f.records, k)
			continue
		}
		var values []string
		for _, rr := range c.ResourceRecordSet.ResourceRecords {
			values = append(values, aws.ToString(rr.Value))
		}
		f.records[k] = values
	}
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &types.ChangeInfo{Id: aws.String("/change/1"), Status: types.ChangeStatusPending}}, nil
}

func (f *fakeR53) GetChange(context.Context, *route53.GetChangeInput, ...func(*route53.Options)) (*route53.GetChangeOutput, error) {
	f.polls++
	status := types.ChangeStatusPending
	if f.polls%2 == 0 {
		status = types.ChangeStatusInsync
	}
	return &route53.GetChangeOutput{ChangeInfo: &types.ChangeInfo{Status: status}}, nil
}

func (f *fakeR53) ListResourceRecordSets(_ context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	values, ok := f.records[key(aws.ToString(in.StartRecordName), in.StartRecordType)]
	if !ok {
		// Route 53 returns the next record in order; make sure callers check the name.
		return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{{Name: aws.String("zzz.covee.io."), Type: in.StartRecordType,
			ResourceRecords: []types.ResourceRecord{{Value: aws.String("198.51.100.1")}}}}}, nil
	}
	var rrs []types.ResourceRecord
	for _, v := range values {
		rrs = append(rrs, types.ResourceRecord{Value: aws.String(v)})
	}
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []types.ResourceRecordSet{{Name: in.StartRecordName, Type: in.StartRecordType, ResourceRecords: rrs}}}, nil
}

func newFake() *fakeR53 {
	return &fakeR53{
		zones: []types.HostedZone{
			{Id: aws.String("/hostedzone/ZPRIVATE"), Name: aws.String("covee.io."), Config: &types.HostedZoneConfig{PrivateZone: true}},
			{Id: aws.String("/hostedzone/ZPUBLIC"), Name: aws.String("covee.io."), Config: &types.HostedZoneConfig{PrivateZone: false}},
		},
		records: map[string][]string{},
	}
}

func TestFindZoneChoosesThePublicZone(t *testing.T) {
	z, err := FindZone(context.Background(), newFake(), "control.covee.io")
	if err != nil {
		t.Fatal(err)
	}
	if z.ZoneID != "ZPUBLIC" || z.Zone != "covee.io" {
		t.Fatalf("got %+v", z)
	}
	if _, err := FindZone(context.Background(), newFake(), "vpn.example.org"); err == nil {
		t.Fatal("found a zone that does not exist")
	}
}

func TestRecordsAreChangedAndAwaited(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := &Route53{API: f, ZoneID: "ZPUBLIC", Zone: "covee.io", Poll: time.Millisecond}
	if got, err := r.CurrentA(ctx, "control.covee.io"); err != nil || len(got) != 0 {
		t.Fatalf("CurrentA on a missing name = %v, %v (must ignore the next record)", got, err)
	}
	if err := r.SetA(ctx, "control.covee.io", "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if f.polls < 2 {
		t.Fatal("did not wait for the change to reach every name server")
	}
	if got, _ := r.CurrentA(ctx, "control.covee.io"); len(got) != 1 || got[0] != "203.0.113.5" {
		t.Fatalf("CurrentA = %v", got)
	}
	if err := r.SetA(ctx, "control.covee.io", "not-an-ip"); err == nil {
		t.Fatal("accepted a bad address")
	}
	name := "_acme-challenge.control.covee.io"
	f.records[key(name+".", types.RRTypeTxt)] = []string{`"other"`}
	if err := r.SetTXT(ctx, name, "token"); err != nil {
		t.Fatal(err)
	}
	if got := f.records[key(name+".", types.RRTypeTxt)]; len(got) != 2 || got[1] != `"token"` {
		t.Fatalf("TXT values = %v", got)
	}
	if err := r.RemoveTXT(ctx, name, "token"); err != nil {
		t.Fatal(err)
	}
	if got := f.records[key(name+".", types.RRTypeTxt)]; len(got) != 1 || got[0] != `"other"` {
		t.Fatalf("other TXT values must stay: %v", got)
	}
	if err := r.RemoveTXT(ctx, name, "other"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.records[key(name+".", types.RRTypeTxt)]; ok {
		t.Fatal("last TXT value should delete the record")
	}
	last := f.changes[len(f.changes)-1]
	if last.Action != types.ChangeActionDelete {
		t.Fatalf("expected a delete, got %v", last.Action)
	}
}
