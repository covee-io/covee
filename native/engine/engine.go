package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	_ "tailscale.com/feature/condregister"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

const maxEventBytes = 1 << 20

type engineConfig struct {
	ControlURL          string `json:"controlURL"`
	Hostname            string `json:"hostname"`
	AuthKey             string `json:"authKey,omitempty"`
	AcceptRoutes        bool   `json:"acceptRoutes"`
	CAPEM               string `json:"caPEM,omitempty"`
	RequireNetworkAck   bool   `json:"requireNetworkAck"`
	TunnelInterfaceName string `json:"tunnelInterfaceName,omitempty"`
}

func parseConfig(raw []byte) (engineConfig, error) {
	var cfg engineConfig
	if len(raw) > 128<<10 {
		return cfg, errors.New("config exceeds 128 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, errors.New("invalid engine config JSON")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("config must contain one JSON object")
	}
	u, err := url.Parse(cfg.ControlURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfg, errors.New("controlURL must be a controller origin without credentials, path, query, or fragment")
	}
	loopback := strings.EqualFold(u.Hostname(), "localhost")
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return cfg, errors.New("controlURL requires HTTPS; HTTP is limited to loopback")
	}
	if len(cfg.Hostname) == 0 || len(cfg.Hostname) > 253 || strings.ContainsAny(cfg.Hostname, "\x00\r\n\t /\\") {
		return cfg, errors.New("hostname is missing or invalid")
	}
	if len(cfg.AuthKey) > 4096 || strings.ContainsAny(cfg.AuthKey, "\x00\r\n") {
		return cfg, errors.New("authKey is invalid")
	}
	if len(cfg.CAPEM) > 64<<10 {
		return cfg, errors.New("caPEM exceeds 64 KiB")
	}
	if len(cfg.TunnelInterfaceName) > 15 {
		return cfg, errors.New("tunnelInterfaceName exceeds interface name limit")
	}
	for _, ch := range cfg.TunnelInterfaceName {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.') {
			return cfg, errors.New("tunnelInterfaceName must contain only ASCII interface name characters")
		}
	}
	return cfg, nil
}

type networkSettings struct {
	Addresses      []string `json:"addresses"`
	Routes         []string `json:"routes"`
	ExcludedRoutes []string `json:"excludedRoutes"`
	DNSServers     []string `json:"dnsServers"`
	MatchDomains   []string `json:"matchDomains"`
	SearchDomains  []string `json:"searchDomains"`
	MTU            int      `json:"mtu"`
	Generation     uint64   `json:"generation"`
}

type peerStatus struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	IPs    []string `json:"ips"`
	Online bool     `json:"online"`
	// ExitNodeOption: the peer offers an exit node that the coordinator approved.
	ExitNodeOption bool `json:"exitNodeOption"`
	// ExitNode: this device currently sends its internet traffic through the peer.
	ExitNode bool `json:"exitNode"`
	// Routes are the local networks the peer currently serves as subnet router.
	Routes []string `json:"routes"`
	// OS is the peer's operating system as it reports it, such as macOS or linux.
	OS string `json:"os,omitempty"`
	// SSHHostKeys are the SSH host keys a peer running Tailscale SSH publishes
	// through the coordinator, which lets people in by their network identity.
	SSHHostKeys []string `json:"sshHostKeys,omitempty"`
}

type engineStatus struct {
	BackendState string       `json:"backendState"`
	IPs          []string     `json:"ips"`
	Peers        []peerStatus `json:"peers"`
	AuthURL      string       `json:"authURL,omitempty"`
	Error        string       `json:"error,omitempty"`
	// MagicDNSSuffix is the network's device name suffix, such as mesh.example.com.
	MagicDNSSuffix string `json:"magicDNSSuffix,omitempty"`
	// ExitNodeID is the chosen exit node's stable ID, or "" for none.
	ExitNodeID             string `json:"exitNodeID"`
	ExitNodeAllowLANAccess bool   `json:"exitNodeAllowLANAccess"`
	// OffersExitNode: this device offers itself as an exit node.
	OffersExitNode bool `json:"offersExitNode"`
	// ExitNodeApproved: the coordinator approved this device's exit node, so
	// other devices can use it.
	ExitNodeApproved bool `json:"exitNodeApproved"`
	// AcceptRoutes: this device uses the routes other devices offer, such as
	// a network gateway's.
	AcceptRoutes bool `json:"acceptRoutes"`
	// Networks are the coordinators this device has a saved sign-in for, so
	// the app can offer them again without typing their address.
	Networks []knownNetwork `json:"networks"`
}

type knownNetwork struct {
	ControlURL string `json:"controlURL"`
	// Suffix is the network's device name suffix, such as mesh.example.com.
	Suffix string `json:"suffix,omitempty"`
}

// canOfferExitNode: a Mac can be an exit node; Apple does not allow it on iPhone.
var canOfferExitNode = runtime.GOOS != "ios"

type engine struct {
	cfg         engineConfig
	store       *keychainStore
	tun         *packetDevice
	done        chan struct{}
	stopOnce    sync.Once
	lifeMu      sync.Mutex
	started     bool
	backend     *ipnlocal.LocalBackend
	netstack    *netstack.Impl
	netmon      *netmon.Monitor
	dialer      *tsdial.Dialer
	ctx         context.Context
	cancel      context.CancelFunc
	workers     sync.WaitGroup
	settings    chan []byte
	statuses    chan []byte
	errors      chan []byte
	eventMu     sync.Mutex
	eventHold   []byte
	packetMu    sync.Mutex
	packetHold  []byte
	errMu       sync.Mutex
	lastError   string
	lastErrorAt time.Time
	ackMu       sync.Mutex
	acks        map[uint64]chan error
	nextGen     atomic.Uint64
	// Final native deliveries/status publication cannot cross a fatal latch.
	// Never hold this lock while calling the backend or waiting for a packet.
	deliveryMu     sync.RWMutex
	fatal          atomic.Bool
	fatalDelivered bool // eventMu
	// Once started, a backend that needs a login gets one sign-in request
	// per time it enters that state (see signInIfNeeded).
	signInReady atomic.Bool
	signInAsked atomic.Bool
	// The coordinator's Noise key, once known, and whether the current
	// sign-in has been recorded as belonging to it (see coordinator.go).
	roots      *x509.CertPool
	controlKey atomic.Pointer[string]
	remembered atomic.Bool
}

// engineLogf receives the backend's log; the app keeps it off. Tests may set it.
var engineLogf logger.Logf = logger.Discard

const persistenceFailure = "Durable client identity could not be saved; tunnel stopped."

var persistenceEvent = []byte(`{"type":"error","code":"persistence","error":"` + persistenceFailure + `"}`)

const (
	// The backend's last notice to a watch it closes for falling behind
	// (watchIPNBusFellBehindMessage in ipnlocal). The engine watches again.
	watchFellBehind = "IPN bus consumer fell behind; closing watch"
	// A passing problem stops showing once the connection has run this long
	// after it.
	staleErrorAge = 2 * time.Minute
	// How long to wait before asking for a sign-in address again after the
	// coordinator could not give one.
	signInRetry = 30 * time.Second
)

func newEngine(cfg engineConfig, store *keychainStore) *engine {
	ctx, cancel := context.WithCancel(context.Background())
	tun := newPacketDevice()
	if cfg.TunnelInterfaceName != "" {
		tun.name = cfg.TunnelInterfaceName
	}
	e := &engine{
		cfg: cfg, store: store, tun: tun, done: make(chan struct{}), ctx: ctx, cancel: cancel,
		settings: make(chan []byte, 8), statuses: make(chan []byte, 1), errors: make(chan []byte, 8),
		acks: make(map[uint64]chan error),
	}
	store.onFailure = e.failPersistence
	return e
}

// WriteState callers may hold backend locks. Close only our packet boundary
// synchronously, then schedule backend shutdown outside every caller/store lock.
func (e *engine) failPersistence() {
	e.deliveryMu.Lock()
	first := !e.fatal.Load()
	if first {
		e.tun.Close()
		e.fatal.Store(true)
		e.errMu.Lock()
		e.lastError = persistenceFailure
		e.errMu.Unlock()
	}
	e.deliveryMu.Unlock()
	if first {
		go e.stop()
	}
}

func (e *engine) start() error {
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	select {
	case <-e.done:
		return io.EOF
	default:
	}
	if e.started {
		return errors.New("engine already started")
	}
	e.started = true
	// This is an embedded self-hosted client. Do not construct a log uploader or
	// advertise support for mandatory diagnostic uploads.
	envknob.SetNoLogsNoSupport()
	logf := engineLogf
	sys := tsd.NewSystem()
	sys.Set(e.store)
	if e.cfg.CAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(e.cfg.CAPEM)) {
			return errors.New("caPEM contains no valid certificates")
		}
		sys.ExtraRootCAs = roots
		e.roots = roots
	}
	nm, err := netmon.New(sys.Bus.Get(), logf)
	if err != nil {
		return fmt.Errorf("initialize network monitor: %w", err)
	}
	e.netmon = nm
	dialer := &tsdial.Dialer{Logf: logf}
	dialer.SetBus(sys.Bus.Get())
	e.dialer = dialer
	routes := &router.CallbackRouter{SetBoth: e.applyNetwork, SplitDNS: true, InitialMTU: 1280}
	wg, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun: e.tun, Router: routes, DNS: routes, NetMon: nm,
		Dialer: dialer, SetSubsystem: sys.Set, EventBus: sys.Bus.Get(),
		HealthTracker: sys.HealthTracker.Get(), Metrics: sys.UserMetricsRegistry(),
		ControlKnobs: sys.ControlKnobs(), ExtraRootCAs: sys.ExtraRootCAs,
	})
	if err != nil {
		return fmt.Errorf("initialize packet engine: %w", err)
	}
	sys.Set(wg)
	sys.Set(dialer)
	sys.HealthTracker.Get().SetMetricsRegistry(sys.UserMetricsRegistry())
	// Netstack answers the network's name service at 100.100.100.100 (device
	// names under the network's DNS suffix) and the other quad-100 services,
	// as in Tailscale's own clients. Traffic to this device still goes through
	// the OS tunnel, so netstack takes no local addresses. On a Mac it relays
	// what other devices send through this one as an exit node, as tailscaled
	// does on macOS; that only happens once the coordinator approves the routes.
	ns, err := netstack.Create(logf, sys.Tun.Get(), sys.Engine.Get(), sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		wg.Close()
		<-wg.Done()
		return fmt.Errorf("initialize name service: %w", err)
	}
	ns.ProcessLocalIPs = false
	ns.ProcessSubnets = canOfferExitNode
	sys.Set(ns)
	e.netstack = ns
	sys.Tun.Get().Start()
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, controlclient.LocalBackendStartKeyOSNeutral)
	if err != nil {
		ns.Close()
		wg.Close()
		<-wg.Done()
		return fmt.Errorf("initialize backend: %w", err)
	}
	if err := ns.Start(lb); err != nil {
		lb.Shutdown()
		ns.Close()
		return fmt.Errorf("start name service: %w", err)
	}
	e.backend = lb
	watchReady := make(chan struct{})
	var watchAdded sync.Once
	e.workers.Add(2)
	go func() {
		defer e.workers.Done()
		for {
			lb.WatchNotifications(e.ctx, ipn.NotifyInitialState|ipn.NotifyNoNetMap, func() { watchAdded.Do(func() { close(watchReady) }) }, func(n *ipn.Notify) bool {
				if n.ErrMessage != nil && *n.ErrMessage != "" && *n.ErrMessage != watchFellBehind {
					e.recordError(errors.New(*n.ErrMessage))
				}
				if n.State != nil && *n.State != ipn.NeedsLogin {
					// Every new need for a login gets its own sign-in request.
					e.signInAsked.Store(false)
				}
				return true
			})
			// The backend closes a watch that falls behind; watch again for
			// the rest of the connection.
			select {
			case <-e.done:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	go func() {
		defer e.workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-e.done:
				return
			case <-ticker.C:
				e.signInIfNeeded(lb)
				e.rememberCoordinator(lb)
				e.publishStatus(lb)
			}
		}
	}()
	select {
	case <-watchReady:
	case <-e.done:
		return io.EOF
	}
	if err := e.useProfileFor(lb); err != nil {
		return err
	}
	prefs := ipn.NewPrefs()
	prefs.Hostname = e.cfg.Hostname
	prefs.ControlURL = e.cfg.ControlURL
	prefs.WantRunning = true
	prefs.RouteAll = e.cfg.AcceptRoutes
	prefs.CorpDNS = true
	if err := lb.Start(ipn.Options{UpdatePrefs: prefs, AuthKey: e.cfg.AuthKey}); err != nil {
		return fmt.Errorf("start backend: %w", err)
	}
	if e.fatal.Load() {
		return errors.New(persistenceFailure)
	}
	if lb.State() == ipn.NeedsLogin && e.cfg.AuthKey == "" {
		e.signInAsked.Store(true)
		if err := lb.StartLoginInteractive(e.ctx); err != nil {
			return fmt.Errorf("start interactive login: %w", err)
		}
	}
	e.signInReady.Store(true)
	e.publishStatus(lb)
	return nil
}

// signInIfNeeded asks the coordinator for a sign-in address when the backend
// comes to need a login after starting, for example when the coordinator no
// longer knows this device or its sign-in expired. Without it the app would
// show "Connecting" until its deadline. It runs on the status ticker, which
// stop waits for before the backend shuts down.
func (e *engine) signInIfNeeded(lb *ipnlocal.LocalBackend) {
	if lb.State() != ipn.NeedsLogin || e.cfg.AuthKey != "" || !e.signInReady.Load() || e.signInAsked.Swap(true) {
		return
	}
	if err := lb.StartLoginInteractive(e.ctx); err != nil && e.ctx.Err() == nil {
		e.recordError(fmt.Errorf("start interactive login: %w", err))
		// The coordinator may be out of reach for a moment; ask again later.
		time.AfterFunc(signInRetry, func() { e.signInAsked.Store(false) })
	}
}

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func domainStrings(domains []dnsname.FQDN) []string {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		out = append(out, strings.TrimSuffix(string(domain), "."))
	}
	return out
}

func (e *engine) applyNetwork(rcfg *router.Config, dcfg *dns.OSConfig) error {
	select {
	case <-e.done:
		return nil
	default:
	}
	n := networkSettings{
		Addresses: []string{}, Routes: []string{}, ExcludedRoutes: []string{}, DNSServers: []string{},
		MatchDomains: []string{}, SearchDomains: []string{}, MTU: e.tun.mtu, Generation: e.nextGen.Add(1),
	}
	if rcfg != nil {
		n.Addresses = prefixStrings(rcfg.LocalAddrs)
		n.Routes = prefixStrings(rcfg.Routes)
		n.ExcludedRoutes = prefixStrings(rcfg.LocalRoutes)
		if rcfg.NewMTU > 0 {
			n.MTU = rcfg.NewMTU
		}
	}
	if dcfg != nil {
		for _, ip := range dcfg.Nameservers {
			n.DNSServers = append(n.DNSServers, ip.String())
		}
		n.MatchDomains, n.SearchDomains = domainStrings(dcfg.MatchDomains), domainStrings(dcfg.SearchDomains)
	}
	raw, err := json.Marshal(struct {
		Type    string          `json:"type"`
		Network networkSettings `json:"network"`
	}{"network", n})
	if err != nil || len(raw) > maxEventBytes {
		return errors.New("network settings exceed event limit")
	}
	var ack chan error
	if e.cfg.RequireNetworkAck {
		ack = make(chan error, 1)
		e.ackMu.Lock()
		e.acks[n.Generation] = ack
		e.ackMu.Unlock()
		defer func() { e.ackMu.Lock(); delete(e.acks, n.Generation); e.ackMu.Unlock() }()
	}
	select {
	case <-e.done:
		return nil
	case e.settings <- raw:
	default:
		return errors.New("network settings consumer is not keeping up")
	}
	if ack == nil {
		return nil
	}
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-e.done:
		return nil
	case err := <-ack:
		return err
	case <-timer.C:
		return errors.New("native network settings acknowledgement timed out")
	}
}

func (e *engine) acknowledge(generation uint64, nativeError string) error {
	e.ackMu.Lock()
	ack := e.acks[generation]
	e.ackMu.Unlock()
	if ack == nil {
		return errors.New("network settings generation is no longer pending")
	}
	var err error
	if nativeError != "" {
		err = errors.New("native network settings failed: " + e.sanitize(nativeError))
	}
	select {
	case ack <- err:
		return nil
	default:
		return errors.New("network settings generation was already acknowledged")
	}
}

func (e *engine) publishStatus(lb *ipnlocal.LocalBackend) {
	if e.fatal.Load() {
		return
	}
	raw, err := json.Marshal(struct {
		Type   string       `json:"type"`
		Status engineStatus `json:"status"`
	}{"status", e.buildStatus(lb)})
	if err != nil || len(raw) > maxEventBytes {
		e.recordError(errors.New("status exceeds event limit"))
		return
	}
	// Only the newest status snapshot matters; never let a paused GUI block
	// coordination or grow memory without bound.
	e.deliveryMu.RLock()
	defer e.deliveryMu.RUnlock()
	if e.fatal.Load() {
		return
	}
	select {
	case <-e.statuses:
	default:
	}
	select {
	case <-e.done:
	case e.statuses <- raw:
	default:
	}
}

// buildStatus is the snapshot publishStatus sends to the app.
func (e *engine) buildStatus(lb *ipnlocal.LocalBackend) engineStatus {
	st := lb.Status()
	status := engineStatus{BackendState: st.BackendState, IPs: []string{}, Peers: []peerStatus{}, AuthURL: st.AuthURL, Networks: []knownNetwork{}}
	for _, p := range lb.ListProfiles() {
		if p.ControlURL() != "" {
			status.Networks = append(status.Networks, knownNetwork{ControlURL: p.ControlURL(), Suffix: strings.TrimSuffix(p.NetworkProfile().MagicDNSName, ".")})
		}
	}
	if st.CurrentTailnet != nil {
		status.MagicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
	}
	if prefs := lb.Prefs(); prefs.Valid() {
		status.ExitNodeID = string(prefs.ExitNodeID())
		status.ExitNodeAllowLANAccess = prefs.ExitNodeAllowLANAccess()
		status.OffersExitNode = tsaddr.ContainsExitRoutes(prefs.AdvertiseRoutes())
		status.AcceptRoutes = prefs.RouteAll()
	}
	if st.Self != nil {
		status.ExitNodeApproved = status.OffersExitNode && st.Self.ExitNodeOption
	}
	for _, ip := range st.TailscaleIPs {
		status.IPs = append(status.IPs, ip.String())
	}
	for _, p := range st.Peer {
		peer := peerStatus{ID: string(p.ID), Name: p.DNSName, IPs: []string{}, Online: p.Online,
			ExitNodeOption: p.ExitNodeOption, ExitNode: p.ExitNode, Routes: []string{},
			OS: p.OS, SSHHostKeys: p.SSH_HostKeys}
		if peer.Name == "" {
			peer.Name = p.HostName
		}
		for _, ip := range p.TailscaleIPs {
			peer.IPs = append(peer.IPs, ip.String())
		}
		if p.PrimaryRoutes != nil {
			peer.Routes = prefixStrings(p.PrimaryRoutes.AsSlice())
		}
		status.Peers = append(status.Peers, peer)
	}
	sort.Slice(status.Peers, func(i, j int) bool { return status.Peers[i].ID < status.Peers[j].ID })
	status.Error = e.currentError(st.BackendState)
	return status
}

// currentError is the problem a status reports. The connection keeps running
// through passing problems, such as a late settings acknowledgement or the
// coordinator out of reach for a moment; once it has run normally for a while
// after one, that problem is no longer news.
func (e *engine) currentError(backendState string) string {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if e.lastError != "" && !e.fatal.Load() && backendState == ipn.Running.String() && time.Since(e.lastErrorAt) > staleErrorAge {
		e.lastError = ""
	}
	return e.lastError
}

type exitNodeRequest struct {
	ID       string `json:"id"`
	AllowLAN bool   `json:"allowLAN"`
}

var (
	errNoExitNode   = errors.New("That device does not offer an exit node. Ask your network administrator to approve it.")
	errOfferingExit = errors.New("This device is an exit node for others. Stop offering it before using another exit node.")
	errUsingExit    = errors.New("Stop using an exit node before offering this device as one.")
	errCannotBeExit = errors.New("Only a Mac can be an exit node; Apple does not allow it on iPhone.")
	errInvalidOffer = errors.New("invalid exit node offer request")
)

// setExitNode routes this device's internet traffic through a peer that
// offers an approved exit node, or through no exit node when the ID is empty.
// It never reports through recordError: a refused choice must not stop the
// tunnel.
func (e *engine) setExitNode(raw []byte) error {
	var req exitNodeRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid exit node request")
	}
	if len(req.ID) > 256 || strings.ContainsAny(req.ID, "\x00\r\n\t ") {
		return errors.New("invalid exit node ID")
	}
	// Holding lifeMu keeps the backend from shutting down during the change.
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	select {
	case <-e.done:
		return io.EOF
	default:
	}
	lb := e.backend
	if lb == nil || e.fatal.Load() {
		return errors.New("the networking engine is not running")
	}
	if req.ID != "" && tsaddr.ContainsExitRoutes(lb.Prefs().AdvertiseRoutes()) {
		return errOfferingExit
	}
	if req.ID != "" {
		offered := false
		for _, p := range lb.Status().Peer {
			if string(p.ID) == req.ID && p.ExitNodeOption {
				offered = true
				break
			}
		}
		if !offered {
			return errNoExitNode
		}
	}
	if _, err := lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs:                     ipn.Prefs{ExitNodeID: tailcfg.StableNodeID(req.ID), ExitNodeAllowLANAccess: req.AllowLAN},
		ExitNodeIDSet:             true,
		ExitNodeAllowLANAccessSet: true,
	}); err != nil {
		return fmt.Errorf("the exit node could not be changed: %s", e.sanitize(err.Error()))
	}
	e.publishStatus(lb)
	return nil
}

// setAcceptRoutes turns the use of routes other devices offer (local networks,
// a gateway's destinations) on or off. Like setExitNode it never stops the
// tunnel.
func (e *engine) setAcceptRoutes(raw []byte) error {
	var req struct {
		Accept *bool `json:"accept"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF || req.Accept == nil {
		return errors.New("invalid routes request")
	}
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	select {
	case <-e.done:
		return io.EOF
	default:
	}
	lb := e.backend
	if lb == nil || e.fatal.Load() {
		return errors.New("the networking engine is not running")
	}
	if _, err := lb.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: *req.Accept}, RouteAllSet: true}); err != nil {
		return fmt.Errorf("the gateway setting could not be changed: %s", e.sanitize(err.Error()))
	}
	e.publishStatus(lb)
	return nil
}

// setOfferExitNode offers this device to the network as an exit node, or
// stops offering it. Other devices can use it only after an administrator
// approves it in the console. Local networks the device offers are kept.
func (e *engine) setOfferExitNode(raw []byte) error {
	var req struct {
		Offer *bool `json:"offer"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF || req.Offer == nil {
		return errInvalidOffer
	}
	if *req.Offer && !canOfferExitNode {
		return errCannotBeExit
	}
	e.lifeMu.Lock()
	defer e.lifeMu.Unlock()
	select {
	case <-e.done:
		return io.EOF
	default:
	}
	lb := e.backend
	if lb == nil || e.fatal.Load() {
		return errors.New("the networking engine is not running")
	}
	prefs := lb.Prefs()
	if *req.Offer && prefs.ExitNodeID() != "" {
		return errUsingExit
	}
	routes := tsaddr.FilterPrefixesCopy(prefs.AdvertiseRoutes(), func(p netip.Prefix) bool { return !tsaddr.IsExitRoute(p) })
	if *req.Offer {
		routes = append(routes, tsaddr.ExitRoutes()...)
	}
	if _, err := lb.EditPrefs(&ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: routes}, AdvertiseRoutesSet: true}); err != nil {
		return fmt.Errorf("the exit node offer could not be changed: %s", e.sanitize(err.Error()))
	}
	e.publishStatus(lb)
	return nil
}

var secretPattern = regexp.MustCompile(`(?i)\b(?:tskey|hskey|privkey|nodekey|mkey)[-_:][a-z0-9_:.-]+`)

func (e *engine) sanitize(message string) string {
	if e.cfg.AuthKey != "" {
		message = strings.ReplaceAll(message, e.cfg.AuthKey, "[redacted]")
	}
	message = secretPattern.ReplaceAllString(message, "[redacted]")
	message = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return ' '
		}
		return r
	}, message)
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

func (e *engine) recordError(err error) {
	if err == nil {
		return
	}
	e.deliveryMu.RLock()
	defer e.deliveryMu.RUnlock()
	if e.fatal.Load() {
		return
	}
	message := e.sanitize(err.Error())
	e.errMu.Lock()
	e.lastError = message
	e.lastErrorAt = time.Now()
	e.errMu.Unlock()
	raw, _ := json.Marshal(struct {
		Type  string `json:"type"`
		Error string `json:"error"`
	}{"error", message})
	select {
	case <-e.done:
	case e.errors <- raw:
	default:
	}
}

func (e *engine) stop() {
	e.stopOnce.Do(func() {
		close(e.done)
		e.cancel()
		e.tun.Close()
		e.lifeMu.Lock()
		defer e.lifeMu.Unlock()
		// Cancel polling before backend Shutdown; status readers never use a
		// LocalBackend after its shutdown has completed.
		e.workers.Wait()
		if e.backend != nil {
			e.backend.Shutdown()
		}
		if e.netstack != nil {
			e.netstack.Close()
		}
		if e.netmon != nil {
			e.netmon.Close()
		}
		if e.dialer != nil {
			e.dialer.Close()
		}
	})
}

func (e *engine) nextEvent(capacity int) ([]byte, int) {
	e.eventMu.Lock()
	defer e.eventMu.Unlock()
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	for {
		e.deliveryMu.RLock()
		if e.fatal.Load() {
			// A previously short-buffered network/Running event is obsolete.
			e.eventHold = nil
			if e.fatalDelivered {
				e.deliveryMu.RUnlock()
				return nil, codeClosed
			}
			if len(persistenceEvent)+1 > capacity {
				e.deliveryMu.RUnlock()
				return nil, codeSmall
			}
			e.fatalDelivered = true
			e.deliveryMu.RUnlock()
			return persistenceEvent, len(persistenceEvent)
		}
		select {
		case <-e.done:
			e.deliveryMu.RUnlock()
			return nil, codeClosed
		default:
		}
		if e.eventHold != nil {
			if len(e.eventHold)+1 > capacity {
				e.deliveryMu.RUnlock()
				return nil, codeSmall
			}
			out := e.eventHold
			e.eventHold = nil
			e.deliveryMu.RUnlock()
			return out, len(out)
		}
		e.deliveryMu.RUnlock()
		select {
		case e.eventHold = <-e.settings:
		default:
		}
		if e.eventHold == nil {
			select {
			case <-e.done:
				// Recheck the sticky fatal event before reporting CLOSED.
			case e.eventHold = <-e.settings:
			case e.eventHold = <-e.errors:
			case e.eventHold = <-e.statuses:
			case <-timer.C:
				return nil, 0
			}
		}
	}
}

func (e *engine) readPacket(capacity int) ([]byte, int) {
	e.packetMu.Lock()
	defer e.packetMu.Unlock()
	select {
	case <-e.tun.done:
		e.packetHold = nil
		return nil, codeClosed
	default:
	}
	if e.packetHold == nil {
		select {
		case <-e.tun.done:
			return nil, codeClosed
		case e.packetHold = <-e.tun.incoming:
		}
	}
	e.deliveryMu.RLock()
	defer e.deliveryMu.RUnlock()
	select {
	case <-e.tun.done:
		e.packetHold = nil
		return nil, codeClosed
	default:
	}
	if len(e.packetHold) > capacity {
		return nil, codeSmall
	}
	out := e.packetHold
	e.packetHold = nil
	return out, len(out)
}
