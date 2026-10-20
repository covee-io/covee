package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The address updater on a home network's server changes the hostname's A
// record with its own AWS key. The key belongs to a dedicated IAM user whose
// only permission is reading the zone and replacing that one record.

// IAMAPI is the part of the IAM client the updater's user needs.
type IAMAPI interface {
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	CreateUser(context.Context, *iam.CreateUserInput, ...func(*iam.Options)) (*iam.CreateUserOutput, error)
	PutUserPolicy(context.Context, *iam.PutUserPolicyInput, ...func(*iam.Options)) (*iam.PutUserPolicyOutput, error)
	DeleteUserPolicy(context.Context, *iam.DeleteUserPolicyInput, ...func(*iam.Options)) (*iam.DeleteUserPolicyOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
	DeleteUser(context.Context, *iam.DeleteUserInput, ...func(*iam.Options)) (*iam.DeleteUserOutput, error)
}

// UpdaterPolicyName is the inline policy on the updater's IAM user.
const UpdaterPolicyName = "covee-dns-updater"

// UpdaterUser names the IAM user of a network's address updater.
func UpdaterUser(network string) string { return "covee-" + network + "-dns" }

// UpdaterPolicy allows reading the zone's records and UPSERTing hostname's A
// record, nothing else.
func UpdaterPolicy(zoneID, hostname string) (string, error) {
	if zoneID == "" || strings.ContainsAny(zoneID, `/"*`) {
		return "", fmt.Errorf("unexpected hosted zone ID %q", zoneID)
	}
	zone := "arn:aws:route53:::hostedzone/" + zoneID
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{"Sid": "ReadTheZone", "Effect": "Allow", "Action": "route53:ListResourceRecordSets", "Resource": zone},
			map[string]any{"Sid": "ReplaceOnlyTheHostnameARecord", "Effect": "Allow", "Action": "route53:ChangeResourceRecordSets", "Resource": zone,
				"Condition": map[string]any{"ForAllValues:StringEquals": map[string]any{
					"route53:ChangeResourceRecordSetsNormalizedRecordNames": []string{strings.ToLower(strings.TrimSuffix(hostname, "."))},
					"route53:ChangeResourceRecordSetsRecordTypes":           []string{"A"},
					"route53:ChangeResourceRecordSetsActions":               []string{"UPSERT"},
				}}},
		},
	}
	b, err := json.Marshal(policy)
	return string(b), err
}

// EnsureUpdaterUser creates the updater's IAM user if needed and sets its
// policy. It returns whether the user was created.
func EnsureUpdaterUser(ctx context.Context, api IAMAPI, network, zoneID, hostname string) (bool, error) {
	user := UpdaterUser(network)
	policy, err := UpdaterPolicy(zoneID, hostname)
	if err != nil {
		return false, err
	}
	created := false
	if _, err := api.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(user)}); err != nil {
		var missing *iamtypes.NoSuchEntityException
		if !errors.As(err, &missing) {
			return false, fmt.Errorf("looking up IAM user %s: %w", user, err)
		}
		if _, err := api.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(user), Path: aws.String("/covee/"), Tags: []iamtypes.Tag{
			{Key: aws.String("covee:network"), Value: aws.String(network)},
			{Key: aws.String("covee:purpose"), Value: aws.String("Keeps " + hostname + " pointing at the public address of the network")},
		}}); err != nil {
			return false, fmt.Errorf("creating IAM user %s: %w", user, err)
		}
		created = true
	}
	if _, err := api.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String(UpdaterPolicyName), PolicyDocument: aws.String(policy)}); err != nil {
		return created, fmt.Errorf("limiting IAM user %s to the %s record: %w", user, hostname, err)
	}
	return created, nil
}

// UpdaterKey is an access key of the updater's IAM user.
type UpdaterKey struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// HasActiveKey reports whether the user still has the given active access key.
func HasActiveKey(ctx context.Context, api IAMAPI, network, keyID string) (bool, error) {
	out, err := api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(UpdaterUser(network))})
	if err != nil {
		return false, fmt.Errorf("listing the access keys of %s: %w", UpdaterUser(network), err)
	}
	for _, k := range out.AccessKeyMetadata {
		if aws.ToString(k.AccessKeyId) == keyID && k.Status == iamtypes.StatusTypeActive {
			return true, nil
		}
	}
	return false, nil
}

// NewUpdaterKey replaces the updater user's access keys with a new one. It is
// used when the stored key is missing or no longer works, so the old keys
// have no usable copy and are deleted first.
func NewUpdaterKey(ctx context.Context, api IAMAPI, network string) (UpdaterKey, error) {
	user := UpdaterUser(network)
	out, err := api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user)})
	if err != nil {
		return UpdaterKey{}, fmt.Errorf("listing the access keys of %s: %w", user, err)
	}
	for _, k := range out.AccessKeyMetadata {
		if _, err := api.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String(user), AccessKeyId: k.AccessKeyId}); err != nil {
			return UpdaterKey{}, fmt.Errorf("deleting the old access key %s of %s: %w", aws.ToString(k.AccessKeyId), user, err)
		}
	}
	created, err := api.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(user)})
	if err != nil {
		return UpdaterKey{}, fmt.Errorf("creating an access key for %s: %w", user, err)
	}
	return UpdaterKey{AccessKeyID: aws.ToString(created.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(created.AccessKey.SecretAccessKey)}, nil
}

// RemoveUpdaterUser deletes the updater's access keys, policy and IAM user.
// A user that no longer exists is not an error.
func RemoveUpdaterUser(ctx context.Context, api IAMAPI, network string) error {
	user := UpdaterUser(network)
	var missing *iamtypes.NoSuchEntityException
	out, err := api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user)})
	if errors.As(err, &missing) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("listing the access keys of %s: %w", user, err)
	}
	for _, k := range out.AccessKeyMetadata {
		if _, err := api.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String(user), AccessKeyId: k.AccessKeyId}); err != nil {
			return fmt.Errorf("deleting access key %s of %s: %w", aws.ToString(k.AccessKeyId), user, err)
		}
	}
	if _, err := api.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String(UpdaterPolicyName)}); err != nil && !errors.As(err, &missing) {
		return fmt.Errorf("deleting the policy of %s: %w", user, err)
	}
	if _, err := api.DeleteUser(ctx, &iam.DeleteUserInput{UserName: aws.String(user)}); err != nil && !errors.As(err, &missing) {
		return fmt.Errorf("deleting IAM user %s: %w", user, err)
	}
	return nil
}
