// Package secrets keeps the network's private keys and client secrets.
//
// Every value is kept in the CLI's private local folder (needed to push it to
// the server again) and, when chosen, in AWS Systems Manager Parameter Store as
// the off-machine copy of record. Values are never printed or logged.
package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ErrExists reports an attempt to replace a secret without asking to.
var ErrExists = errors.New("a different value is already stored under this name")

// SSMAPI is the part of the Parameter Store client this package uses.
type SSMAPI interface {
	PutParameter(context.Context, *ssm.PutParameterInput, ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Store keeps one network's secrets.
type Store struct {
	Local  string // private directory, created with mode 0700
	SSM    SSMAPI // nil when only local storage was chosen
	Prefix string // Parameter Store name prefix, for example /covee/home/
}

// Ref returns where a named secret lives, for the network record.
func (s *Store) Ref(name string) string {
	if s.SSM != nil {
		return s.Prefix + name
	}
	return filepath.Join(s.Local, name)
}

func check(name string, value []byte) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	if len(value) == 0 || len(value) > 4096 || !utf8.Valid(value) {
		return fmt.Errorf("secret %s must be 1 to 4096 bytes of text", name)
	}
	return nil
}

// Put stores a new secret and verifies every copy by reading it back.
// Storing the same value again is allowed; a different value needs replace.
func (s *Store) Put(ctx context.Context, name string, value []byte, description string, replace bool) error {
	if err := check(name, value); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Local, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Local, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.Local, name)
	if old, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(old, value) && !replace {
			return fmt.Errorf("%s: %w", name, ErrExists)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writePrivate(path, value); err != nil {
		return err
	}
	if back, err := os.ReadFile(path); err != nil || !bytes.Equal(back, value) {
		return fmt.Errorf("%s: local copy did not read back identically", name)
	}
	if s.SSM == nil {
		return nil
	}
	param := s.Prefix + name
	existing, err := s.SSM.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(param), WithDecryption: aws.Bool(true)})
	var missing *types.ParameterNotFound
	switch {
	case err == nil:
		if aws.ToString(existing.Parameter.Value) == string(value) {
			return nil
		}
		if !replace {
			return fmt.Errorf("Parameter Store %s: %w", param, ErrExists)
		}
	case errors.As(err, &missing):
	default:
		return fmt.Errorf("Parameter Store %s: %w", param, err)
	}
	_, err = s.SSM.PutParameter(ctx, &ssm.PutParameterInput{
		Name:        aws.String(param),
		Type:        types.ParameterTypeSecureString,
		KeyId:       aws.String("alias/aws/ssm"),
		Tier:        types.ParameterTierStandard,
		Description: aws.String(description),
		Value:       aws.String(string(value)),
		Overwrite:   aws.Bool(replace),
	})
	if err != nil {
		return fmt.Errorf("Parameter Store %s: %w", param, err)
	}
	back, err := s.SSM.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(param), WithDecryption: aws.Bool(true)})
	if err != nil {
		return fmt.Errorf("Parameter Store %s: reading back: %w", param, err)
	}
	if aws.ToString(back.Parameter.Value) != string(value) {
		return fmt.Errorf("Parameter Store %s: value did not read back identically", param)
	}
	return nil
}

// Get returns a secret from the local copy, or from Parameter Store when the
// local copy is missing (for example on another computer), restoring it locally.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("invalid secret name %q", name)
	}
	path := filepath.Join(s.Local, name)
	value, err := os.ReadFile(path)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) || s.SSM == nil {
		return nil, fmt.Errorf("secret %s is not available: %w", name, err)
	}
	out, err := s.SSM.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(s.Prefix + name), WithDecryption: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	value = []byte(aws.ToString(out.Parameter.Value))
	if err := os.MkdirAll(s.Local, 0o700); err != nil {
		return nil, err
	}
	if err := writePrivate(path, value); err != nil {
		return nil, err
	}
	return value, nil
}

// Path returns the local file holding a secret, fetching it first if needed.
func (s *Store) Path(ctx context.Context, name string) (string, error) {
	if _, err := s.Get(ctx, name); err != nil {
		return "", err
	}
	return filepath.Join(s.Local, name), nil
}

// writePrivate replaces path with a mode 0400 file without a window in which
// another user could read it.
func writePrivate(path string, value []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secret-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o400); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(value); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
