package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSSM struct {
	values map[string]string
	puts   []*ssm.PutParameterInput
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	name := aws.ToString(in.Name)
	if _, ok := f.values[name]; ok && !aws.ToBool(in.Overwrite) {
		return nil, &types.ParameterAlreadyExists{}
	}
	f.puts = append(f.puts, in)
	f.values[name] = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	v, ok := f.values[aws.ToString(in.Name)]
	if !ok {
		return nil, &types.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &types.Parameter{Value: aws.String(v)}}, nil
}

func TestLocalOnlyStore(t *testing.T) {
	ctx := context.Background()
	s := &Store{Local: filepath.Join(t.TempDir(), "home")}
	if err := s.Put(ctx, "ssh-private-key", []byte("one"), "d", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "ssh-private-key", []byte("one"), "d", false); err != nil {
		t.Fatalf("same value again must be allowed: %v", err)
	}
	if err := s.Put(ctx, "ssh-private-key", []byte("two"), "d", false); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if err := s.Put(ctx, "ssh-private-key", []byte("two"), "d", true); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "ssh-private-key")
	if err != nil || string(got) != "two" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	info, _ := os.Stat(filepath.Join(s.Local, "ssh-private-key"))
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("secret mode %v", info.Mode().Perm())
	}
	dir, _ := os.Stat(s.Local)
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode %v", dir.Mode().Perm())
	}
	if s.Ref("x") != filepath.Join(s.Local, "x") {
		t.Fatal("local reference should be the file path")
	}
	for _, bad := range [][]byte{nil, make([]byte, 4097), {0xff, 0xfe}} {
		if err := s.Put(ctx, "other", bad, "d", false); err == nil {
			t.Errorf("accepted invalid value of %d bytes", len(bad))
		}
	}
	if err := s.Put(ctx, "../escape", []byte("x"), "d", false); err == nil {
		t.Fatal("accepted a path-like name")
	}
}

func TestParameterStoreCopyIsVerifiedAndProtected(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSSM{values: map[string]string{}}
	s := &Store{Local: t.TempDir(), SSM: fake, Prefix: "/covee/home/"}
	if err := s.Put(ctx, "tls-private-key", []byte("key"), "TLS key.", false); err != nil {
		t.Fatal(err)
	}
	in := fake.puts[0]
	if aws.ToString(in.Name) != "/covee/home/tls-private-key" || in.Type != types.ParameterTypeSecureString ||
		aws.ToString(in.KeyId) != "alias/aws/ssm" || in.Tier != types.ParameterTierStandard || aws.ToBool(in.Overwrite) {
		t.Fatalf("unexpected parameter: %+v", in)
	}
	if s.Ref("tls-private-key") != "/covee/home/tls-private-key" {
		t.Fatal("reference should be the parameter name")
	}
	// Same value: no second write.
	if err := s.Put(ctx, "tls-private-key", []byte("key"), "TLS key.", false); err != nil || len(fake.puts) != 1 {
		t.Fatalf("rewrote an identical value: %v, %d", err, len(fake.puts))
	}
	// A different value already in Parameter Store needs replace.
	fake.values["/covee/home/apple-private-key"] = "old"
	if err := s.Put(ctx, "apple-private-key", []byte("new"), "d", false); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	if err := s.Put(ctx, "apple-private-key", []byte("new"), "d", true); err != nil || fake.values["/covee/home/apple-private-key"] != "new" {
		t.Fatalf("replace failed: %v", err)
	}
	// Another computer: the local copy is restored from Parameter Store.
	other := &Store{Local: filepath.Join(t.TempDir(), "elsewhere"), SSM: fake, Prefix: "/covee/home/"}
	got, err := other.Get(ctx, "tls-private-key")
	if err != nil || string(got) != "key" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if b, _ := os.ReadFile(filepath.Join(other.Local, "tls-private-key")); string(b) != "key" {
		t.Fatal("local copy not restored")
	}
}
