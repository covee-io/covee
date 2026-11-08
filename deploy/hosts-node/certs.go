package main

import (
	"crypto/tls"
	"errors"
	"sync"
	"time"
)

// certificate serves the network's public certificate (which covers every
// name under the mesh domain) from two files that deploy.py replaces by
// renaming when it renews them. The files are looked at again at most once
// every `every`, and loaded again when either one changed. A pair that does
// not load, for example while one file has been replaced and the other not
// yet, leaves the previous certificate in use.
type certificate struct {
	certPath, keyPath string
	every             time.Duration
	logf              func(string, ...any)

	mu                  sync.Mutex
	cert                *tls.Certificate
	certStamp, keyStamp fileStamp
	checked             time.Time
	lastErr             string
}

func (c *certificate) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checked.IsZero() || time.Since(c.checked) >= c.every {
		c.refresh()
	}
	if c.cert == nil {
		return nil, errors.New("no certificate is installed yet")
	}
	return c.cert, nil
}

// refresh must be called with c.mu held.
func (c *certificate) refresh() {
	c.checked = time.Now()
	certStamp, err1 := stampOf(c.certPath)
	keyStamp, err2 := stampOf(c.keyPath)
	if err := errors.Join(err1, err2); err != nil {
		c.report(err)
		return
	}
	if c.cert != nil && certStamp.same(c.certStamp) && keyStamp.same(c.keyStamp) {
		return
	}
	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		if c.cert != nil {
			c.report(errors.New(err.Error() + "; keeping the certificate in use"))
		} else {
			c.report(err)
		}
		return
	}
	c.cert, c.certStamp, c.keyStamp, c.lastErr = &cert, certStamp, keyStamp, ""
	if cert.Leaf != nil {
		c.logf("certificate: loaded, valid until %s", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}

// report logs an error once, not on every check.
func (c *certificate) report(err error) {
	if msg := err.Error(); msg != c.lastErr {
		c.logf("certificate: %s", msg)
		c.lastErr = msg
	}
}
