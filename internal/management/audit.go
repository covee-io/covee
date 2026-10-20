package management

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AuditEvent struct {
	ID        string `json:"id"`
	Time      string `json:"time"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Outcome   string `json:"outcome"`
	RequestID string `json:"requestId"`
	Actor     Actor  `json:"actor"`
}
type auditFile interface {
	io.Writer
	Sync() error
	Close() error
}
type auditLog struct {
	mu     sync.Mutex
	file   auditFile
	events []AuditEvent
	failed bool
}

func openAudit(dir string) (*auditLog, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("audit data path must be a real directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "audit.jsonl")
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("audit path must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	info, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() > 0 {
		var tail [1]byte
		if _, err = f.ReadAt(tail[:], info.Size()-1); err != nil {
			f.Close()
			return nil, err
		}
		if tail[0] != '\n' {
			f.Close()
			return nil, errors.New("audit log has an unterminated record; preserve and repair it before restart")
		}
	}
	a := &auditLog{file: f, events: []AuditEvent{}}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 64<<10)
	for scan.Scan() {
		var ev AuditEvent
		if err := json.Unmarshal(scan.Bytes(), &ev); err != nil {
			f.Close()
			return nil, errors.New("audit log has invalid or truncated records; preserve and repair it before restart")
		}
		a.remember(ev)
	}
	if err := scan.Err(); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	d, err := os.Open(dir)
	if err != nil {
		f.Close()
		return nil, err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		f.Close()
		return nil, err
	}
	return a, nil
}
func (a *auditLog) remember(ev AuditEvent) {
	a.events = append(a.events, ev)
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
}
func (a *auditLog) append(action, target, outcome, requestID string, actor Actor) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed {
		return errors.New("audit unavailable")
	}
	ev := AuditEvent{ID: randomToken(), Time: time.Now().UTC().Format(time.RFC3339Nano), Action: action, Target: target, Outcome: outcome, RequestID: requestID, Actor: actor}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := a.file.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = a.file.Sync()
	}
	if err != nil {
		a.failed = true
		return err
	}
	a.remember(ev)
	return nil
}
func (a *auditLog) latest() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, len(a.events))
	for i := range a.events {
		out[i] = a.events[len(a.events)-1-i]
	}
	return out
}
func (a *auditLog) close() error { a.mu.Lock(); defer a.mu.Unlock(); return a.file.Close() }
