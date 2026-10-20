package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"covee.io/cli/internal/record"
	"covee.io/cli/internal/remote"
)

const (
	labelExisting  = "An existing Ubuntu 24.04 server I can reach with ssh"
	labelProxmox   = "A new VM on my Proxmox host"
	labelSizeStd   = "4 CPUs, 8 GB memory, 64 GB disk (recommended)"
	labelSizeSmall = "2 CPUs, 4 GB memory, 32 GB disk (small)"
)

type proxmoxFacts struct {
	Node         string `json:"node"`
	NextVMID     int    `json:"next_vmid"`
	UsedVMIDs    []int  `json:"used_vmids"`
	DiskStorages []struct {
		ID      string `json:"id"`
		FreeGiB int    `json:"free_gib"`
	} `json:"disk_storages"`
	SnippetStorages []struct {
		ID        string `json:"id"`
		Directory string `json:"directory"`
	} `json:"snippet_storages"`
	Bridges     []string `json:"bridges"`
	Gateway     string   `json:"gateway"`
	HostCIDR    string   `json:"host_cidr"`
	SSHClient   string   `json:"ssh_client"`
	CachedImage bool     `json:"cached_image"`
	Version     string   `json:"version"`
}

func (s *session) proxmoxServer(p *record.Proxmox) *server {
	return &server{
		admin:   &remote.Host{Address: p.Host, User: p.User, KnownHosts: s.server(false).admin.KnownHosts, Binary: s.env.SSH},
		out:     s.env.Out,
		archive: s.archive,
		digest:  s.digest,
	}
}

func sudoPrefix(user string) string {
	if user == "root" {
		return ""
	}
	return "sudo -n "
}

// askProxmox asks where and how big the new VM is. It changes nothing.
func (s *session) askProxmox(ctx context.Context, n *record.Network) (net.IP, error) {
	ask := s.env.Ask
	p := &record.Proxmox{}
	var err error
	if p.Host, err = ask.Text("proxmox_host", "Proxmox host address (the IP or name you use with ssh)", "", func(v string) error {
		if strings.ContainsAny(v, " @'\"`$;") {
			return errors.New("type just the address, without a user name")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if p.User, err = ask.Text("proxmox_user", "SSH user on the Proxmox host", "root", func(v string) error {
		if !regexpUser.MatchString(v) {
			return errors.New("type a user name")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	srv := s.proxmoxServer(p)
	s.say("  Connecting to %s@%s...", p.User, p.Host)
	dir, err := srv.stageAdmin(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w\n  Make sure `ssh %s@%s` works from this computer without a password prompt", err, p.User, p.Host)
	}
	out, err := srv.admin.Output(ctx, sudoPrefix(p.User)+"python3 "+remote.Quote(dir+"/scripts/proxmox_host.py")+" facts", nil)
	srv.cleanupAdmin(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("reading the Proxmox host's options: %w", err)
	}
	var f proxmoxFacts
	if err := lastJSON(out, &f); err != nil {
		return nil, err
	}
	s.say("  Proxmox node %s (%s)", f.Node, strings.SplitN(f.Version, " ", 2)[0])
	if len(f.SnippetStorages) == 0 {
		return nil, errors.New("no Proxmox storage accepts cloud-init snippets; in Datacenter → Storage, enable the \"Snippets\" content type on a directory storage, then run setup again")
	}
	if len(f.DiskStorages) == 0 || len(f.Bridges) == 0 {
		return nil, errors.New("the Proxmox host has no active disk storage or network bridge")
	}
	p.Node = f.Node
	used := map[int]bool{}
	for _, id := range f.UsedVMIDs {
		used[id] = true
	}
	vmid, err := ask.Text("vm_id", "VM ID for the new VM", strconv.Itoa(f.NextVMID), func(v string) error {
		id, err := strconv.Atoi(v)
		if err != nil || id < 100 || id > 999999999 {
			return errors.New("use a number of 100 or more")
		}
		if used[id] {
			return fmt.Errorf("VM ID %d is already in use", id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.VMID, _ = strconv.Atoi(vmid)
	var storages []string
	for _, d := range f.DiskStorages {
		storages = append(storages, d.ID)
		s.say("    storage %s: %d GB free", d.ID, d.FreeGiB)
	}
	if p.Storage, err = ask.Choose("vm_storage", "Storage for the VM's disk", storages, storages[0]); err != nil {
		return nil, err
	}
	p.SnippetStorage, p.SnippetDir = f.SnippetStorages[0].ID, f.SnippetStorages[0].Directory
	if len(f.SnippetStorages) > 1 {
		var ids []string
		for _, sn := range f.SnippetStorages {
			ids = append(ids, sn.ID)
		}
		choice, err := ask.Choose("vm_snippets", "Storage for the VM's cloud-init settings", ids, ids[0])
		if err != nil {
			return nil, err
		}
		for _, sn := range f.SnippetStorages {
			if sn.ID == choice {
				p.SnippetStorage, p.SnippetDir = sn.ID, sn.Directory
			}
		}
	}
	defBridge := f.Bridges[0]
	for _, b := range f.Bridges {
		if b == "vmbr0" {
			defBridge = b
		}
	}
	if p.Bridge, err = ask.Choose("vm_bridge", "Network bridge", f.Bridges, defBridge); err != nil {
		return nil, err
	}
	example := "192.168.1.50/24"
	if _, lan, err := net.ParseCIDR(f.HostCIDR); err == nil {
		ones, _ := lan.Mask.Size()
		example = fmt.Sprintf("an unused address in %s, with /%d", lan, ones)
	}
	cidr, err := ask.Text("vm_address", "Fixed address for the VM ("+example+")", "", func(v string) error {
		ip, network, err := net.ParseCIDR(v)
		if err != nil || ip.To4() == nil {
			return errors.New("type an IPv4 address with its network size, such as 192.168.1.50/24")
		}
		ones, _ := network.Mask.Size()
		if ones < 8 || ones > 30 || ip.Equal(network.IP) {
			return errors.New("use a host address in a network between /8 and /30")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	vmIP, vmNet, _ := net.ParseCIDR(cidr)
	ones, _ := vmNet.Mask.Size()
	cidr = fmt.Sprintf("%s/%d", vmIP, ones)
	if p.Gateway, err = ask.Text("vm_gateway", "Gateway for the VM", f.Gateway, func(v string) error {
		if err := checkIPv4(v); err != nil {
			return err
		}
		if !vmNet.Contains(net.ParseIP(v)) || net.ParseIP(v).Equal(vmIP) {
			return errors.New("the gateway must be another address in the VM's network")
		}
		return nil
	}); err != nil {
		return nil, err
	}
	dns, err := ask.Text("vm_dns", "DNS server for the VM", p.Gateway, checkIPv4)
	if err != nil {
		return nil, err
	}
	p.DNSServers = []string{dns}
	size, err := ask.Choose("vm_size", "VM size", []string{labelSizeStd, labelSizeSmall}, labelSizeStd)
	if err != nil {
		return nil, err
	}
	p.Cores, p.MemoryMiB, p.DiskGiB = 4, 8192, 64
	if size == labelSizeSmall {
		p.Cores, p.MemoryMiB, p.DiskGiB = 2, 4096, 32
	}
	p.Name = "covee-" + n.Name
	n.Server = record.Server{Kind: "proxmox", Address: vmIP.String(), ServiceUser: "covee", Interface: "eth0", IPv4CIDR: cidr, Proxmox: p}
	client := net.ParseIP(f.SSHClient)
	if client == nil || client.To4() == nil {
		return nil, errors.New("could not tell which address you are connecting from")
	}
	return client, nil
}

// publicIPv4 asks a public service which address this computer's internet
// traffic comes from. Used only as a suggestion.
func (s *session) publicIPv4(ctx context.Context) string {
	client := s.env.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://checkip.amazonaws.com", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil || ip.To4() == nil || ip.IsPrivate() {
		return ""
	}
	return ip.String()
}

// stepVM creates and starts the VM on the Proxmox host.
func (s *session) stepVM(ctx context.Context) error {
	p := s.n.Server.Proxmox
	srv := s.proxmoxServer(p)
	if out, err := srv.admin.Output(ctx, sudoPrefix(p.User)+"qm config "+strconv.Itoa(p.VMID)+" 2>/dev/null | sed -n 's/^name: //p'", nil); err == nil {
		if name := strings.TrimSpace(string(out)); name == p.Name {
			s.say("  VM %d (%s) exists from an earlier attempt.", p.VMID, p.Name)
			return nil
		} else if name != "" {
			return fmt.Errorf("VM ID %d now belongs to %q; run setup again with another ID", p.VMID, name)
		}
	}
	pub, err := s.publicKey(ctx)
	if err != nil {
		return err
	}
	dir, err := srv.stageAdmin(ctx)
	if err != nil {
		return err
	}
	defer srv.cleanupAdmin(ctx, dir)
	req := map[string]any{
		"node": p.Node, "vmid": p.VMID, "name": p.Name, "disk_storage": p.Storage, "snippet_storage": p.SnippetStorage,
		"snippet_directory": p.SnippetDir, "bridge": p.Bridge, "network_interface": s.n.Server.Interface, "vlan_tag": nil,
		"ipv4_cidr": s.n.Server.IPv4CIDR, "gateway_ipv4": p.Gateway, "dns_servers": p.DNSServers,
		"ssh_source_cidrs": s.n.Server.SSHSources, "ssh_public_key": pub, "control_host": s.n.Hostname,
		"cores": p.Cores, "memory_mib": p.MemoryMiB, "disk_gib": p.DiskGiB,
	}
	in, _ := json.Marshal(req)
	out, err := srv.admin.Output(ctx, sudoPrefix(p.User)+"python3 "+remote.Quote(dir+"/scripts/proxmox_host.py")+" create", in)
	var result struct {
		VMID        int  `json:"vmid"`
		ImageReused bool `json:"image_reused"`
	}
	if jerr := lastJSON(out, &result); jerr != nil {
		if err == nil {
			err = jerr
		}
		return fmt.Errorf("creating the VM: %w", jerr)
	}
	if err != nil {
		return err
	}
	s.say("  VM %d created and started. Cloud-init now installs updates, the firewall and Docker.", result.VMID)
	return nil
}

// stepVMReady waits until cloud-init has finished preparing the VM.
func (s *session) stepVMReady(ctx context.Context) error {
	srv := s.server(true)
	deadline := time.Now().Add(30 * time.Minute)
	next := time.Now().Add(2 * time.Minute)
	for {
		out, err := srv.covee.Output(ctx, "test -f /var/lib/covee-bootstrap-complete && echo ready", nil)
		if err == nil && strings.TrimSpace(string(out)) == "ready" {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("the VM did not finish preparing within 30 minutes; check its console in Proxmox")
		}
		if time.Now().After(next) {
			s.say("  still preparing...")
			next = time.Now().Add(2 * time.Minute)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(vmPoll):
		}
	}
	if err := srv.checkCovee(ctx); err != nil {
		return err
	}
	if _, err := srv.covee.Output(ctx, "docker info --format '{{.ServerVersion}}'", nil); err != nil {
		return fmt.Errorf("Docker is not working on the VM: %w", err)
	}
	s.say("  The VM is ready.")
	return nil
}

// vmPoll is how often stepVMReady checks the VM (tests shorten it).
var vmPoll = 15 * time.Second
