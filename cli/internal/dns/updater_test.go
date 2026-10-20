package dns

import (
	"encoding/json"
	"testing"
)

func TestUpdaterPolicyAllowsOnlyTheHostnameARecord(t *testing.T) {
	doc, err := UpdaterPolicy("Z0EXAMPLE12345678", "Covee.Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Statement []struct {
			Effect, Action, Resource string
			Condition                map[string]map[string][]string
		}
	}
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Statement) != 2 {
		t.Fatalf("statements = %+v", policy.Statement)
	}
	read, change := policy.Statement[0], policy.Statement[1]
	zone := "arn:aws:route53:::hostedzone/Z0EXAMPLE12345678"
	if read.Action != "route53:ListResourceRecordSets" || read.Resource != zone || read.Condition != nil {
		t.Fatalf("read statement = %+v", read)
	}
	limits := change.Condition["ForAllValues:StringEquals"]
	if change.Action != "route53:ChangeResourceRecordSets" || change.Resource != zone ||
		len(limits["route53:ChangeResourceRecordSetsNormalizedRecordNames"]) != 1 || limits["route53:ChangeResourceRecordSetsNormalizedRecordNames"][0] != "covee.example.com" ||
		len(limits["route53:ChangeResourceRecordSetsRecordTypes"]) != 1 || limits["route53:ChangeResourceRecordSetsRecordTypes"][0] != "A" ||
		len(limits["route53:ChangeResourceRecordSetsActions"]) != 1 || limits["route53:ChangeResourceRecordSetsActions"][0] != "UPSERT" {
		t.Fatalf("change statement = %+v", change)
	}
	for _, bad := range []string{"", "Z1/*", `Z1"`} {
		if _, err := UpdaterPolicy(bad, "covee.example.com"); err == nil {
			t.Fatalf("zone %q accepted", bad)
		}
	}
}
