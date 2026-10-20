#!/usr/bin/env python3
"""Prepare and operate only an explicitly selected portable Covee runtime.

Preparation is offline and does not change host trust, DNS, firewall or SSH.
The check command runs a separate internal-only Docker project with no host ports.
"""

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / ".cache/covee/deploy/runtime"
COMPOSE = ROOT / "deploy/compose.yaml"
IDENTITY_COMPOSE = ROOT / "deploy/compose.identity.yaml"
IDENTITY_BOOTSTRAP_COMPOSE = ROOT / "deploy/compose.identity-bootstrap.yaml"
IMAGES = {"headscale": "covee-headscale:hardened-local",
          "management": "covee-management:portable-local",
          "ingress": "covee-ingress:portable-local"}
IDENTITY_IMAGE = "covee-identity:portable-local"
# The admin console inside the network (spec field console_in_network).
CONSOLE_COMPOSE = ROOT / "deploy/compose.console-network.yaml"
CONSOLE_NODE_IMAGE = "covee-console-node:portable-local"
CONSOLE_TAG = "tag:covee-console"
CONSOLE_NODE_STATE = "state/console-node"
# The console node writes this once it has joined; until then it needs a join key.
# (tsnet's own tailscaled.state appears before a join succeeds, so it is no sign.)
CONSOLE_NODE_IDENTITY = "covee-joined"
CONSOLE_JOIN_KEY = "join-key"
# The gateway device, which carries members to private networks (spec field gateway).
GATEWAY_COMPOSE = ROOT / "deploy/compose.gateway.yaml"
GATEWAY_IMAGE = "covee-gateway:portable-local"
GATEWAY_TAG = "tag:covee-gateway"
GATEWAY_STATE = "state/gateway"
# The management service keeps the console's gateway settings here: the gateway
# reads routes.json, and apply-gateway-dns applies dns.json.
GATEWAY_CONFIG = "state/management/gateway"
IDENTITY_CONFIG_FILES = ("identity.json", "identity-internal.crt", "identity-internal.key", "identity-trust.pem")
# Local Covee accounts (passkeys, passwords) live in this broker-owned state file.
LOCAL_ACCOUNTS_FILE = "/var/lib/covee-identity/accounts.json"
PROVIDER_KINDS = ("entra", "google", "apple", "local")
CONFIG_FILES = ("headscale.yaml", "management.env", "initial-policy.hujson",
                "internal-ca.crt", "internal-ca.key", "headscale-internal.crt",
                "headscale-internal.key", "management-internal.crt", "management-internal.key",
                "ingress-control.crt", "ingress-control.key", "ingress-admin.crt", "ingress-admin.key")
SECRET_FILES = ("admin-token", "headscale-api-key", "oidc-client-secret", "entra-client-secret")


class DeploymentError(RuntimeError):
    pass


def run(args, *, timeout=60, data=None, env=None, check=True):
    try:
        result = subprocess.run([str(arg) for arg in args], input=data, capture_output=True,
                                timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DeploymentError(f"Could not execute {Path(str(args[0])).name}; check prerequisites or timeout") from error
    if check and result.returncode:
        # Output may contain credentials or authentication URLs. Never echo it.
        raise DeploymentError(f"{Path(str(args[0])).name} failed (exit {result.returncode}); output suppressed to protect credentials")
    return result


def write_private(path, data, *, mode=0o400):
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
    path.chmod(mode)


def replace_private(path, data, *, mode=0o400):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    write_private(temporary, data, mode=mode)
    os.replace(temporary, path)


def load_json(path):
    try:
        if path.stat().st_size > 1 << 20:
            raise ValueError("oversized")
        return json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise DeploymentError("Invalid or unreadable deployment JSON") from error


def hostname(value, *, lab=False):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower():
        raise DeploymentError("Hostnames must be lowercase DNS names")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise DeploymentError("Invalid DNS hostname")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           for label in value.split(".")):
        raise DeploymentError("Invalid DNS hostname labels")
    if not lab and value != "localhost" and "." not in value:
        raise DeploymentError("Production hostnames must be fully qualified")
    return value


def validate_expiry(value):
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,3}(?:h|d)", value):
        raise DeploymentError("node_expiry must be a nonzero duration between one hour and 365 days")
    hours = int(value[:-1]) * (24 if value[-1] == "d" else 1)
    if hours > 365 * 24:
        raise DeploymentError("node_expiry must be a nonzero duration between one hour and 365 days")


DNS_KEYS = {"override_local_dns", "nameservers", "split", "search_domains", "extra_records"}
# Limits keep the map pushed to every client small and stay under resolver search-list limits.
DNS_MAX_RESOLVERS, DNS_MAX_SPLIT, DNS_MAX_SEARCH, DNS_MAX_RECORDS = 8, 32, 6, 128
# The client's own forwarder. A resolver pointing at it would loop every query.
CLIENT_RESOLVER = ipaddress.ip_address("100.100.100.100")
THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


def dns_name(value, what):
    """A lowercase DNS name or suffix without a trailing dot; a single label is allowed."""
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.lower():
        raise DeploymentError(f"{what} must be a lowercase DNS name without a trailing dot")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise DeploymentError(f"{what} contains an invalid DNS label")
    return value


def dns_address(value, what):
    """An address that is useful to a client: not a loopback, wildcard, multicast, link-local or reserved one."""
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("scoped or non-string address")
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise DeploymentError(f"{what} must be a plain IPv4 or IPv6 address") from error
    if (address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local
            or address.is_reserved or address == CLIENT_RESOLVER or getattr(address, "ipv4_mapped", None)
            or (address.version == 4 and address in THIS_NETWORK)):
        raise DeploymentError(f"{what} must not be a loopback, wildcard, multicast, link-local, reserved or client-resolver address")
    return address


def dns_resolver(value):
    """Headscale forwards anything that parses as an IP or a URL and only logs the rest, so accept exactly the two usable forms."""
    if not isinstance(value, str) or not value or len(value) > 253 or any(ord(ch) < 33 or ord(ch) > 126 or ch in "'\"\\$`" for ch in value):
        raise DeploymentError("DNS resolvers must be printable ASCII IP addresses or HTTPS URLs")
    if not value.startswith("https://"):
        dns_address(value, "A DNS resolver")
        return value
    # Every client receives this value, so it must not carry credentials or a bearer-style query.
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as error:
        raise DeploymentError("DNS-over-HTTPS resolver URL is invalid") from error
    host = url.hostname
    if not host or url.username or url.password or url.query or url.fragment or (port is not None and not 1 <= port <= 65535):
        raise DeploymentError("DNS-over-HTTPS resolvers must be credential-free URLs without a query or fragment")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if "." not in dns_name(host, "DNS-over-HTTPS resolver host"):
            raise DeploymentError("DNS-over-HTTPS resolver hosts must be fully qualified") from None
    else:
        dns_address(host, "A DNS-over-HTTPS resolver host")
    segments = url.path.split("/")[1:] if url.path else []
    if url.path and (not url.path.startswith("/") or any(not re.fullmatch(r"[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,63}", s) for s in segments)):
        raise DeploymentError("DNS-over-HTTPS resolver paths must be plain, normalized segments")
    return value


def dns_resolvers(values, what):
    if not isinstance(values, list) or len(values) > DNS_MAX_RESOLVERS:
        raise DeploymentError(f"{what} must be a list of at most {DNS_MAX_RESOLVERS} resolvers")
    seen = set()
    for value in values:
        dns_resolver(value)
        key = str(ipaddress.ip_address(value)) if not value.startswith("https://") else value
        if key in seen:
            raise DeploymentError(f"{what} contains a duplicate resolver")
        seen.add(key)
    return list(values)


def validate_dns(dns, spec):
    """Return the canonical custom DNS settings, or {} when nothing is customized.

    Headscale accepts a looser shape and would only log a bad entry, so a
    mistake here would otherwise reach every client. Reject instead.
    """
    if dns is None or dns == {}:
        return {}
    if not isinstance(dns, dict) or set(dns) - DNS_KEYS:
        raise DeploymentError("DNS settings contain unknown fields")
    override = dns.get("override_local_dns", False)
    if type(override) is not bool:
        raise DeploymentError("override_local_dns must be true or false")
    nameservers = dns_resolvers(dns.get("nameservers", []), "Global nameservers")
    if override and not nameservers:
        raise DeploymentError("override_local_dns requires at least one global nameserver")
    base, hosts = spec["dns_base_domain"], (spec["control_host"], spec["admin_host"])
    raw_split = dns.get("split", {})
    if not isinstance(raw_split, dict) or len(raw_split) > DNS_MAX_SPLIT:
        raise DeploymentError(f"Split DNS must be an object mapping at most {DNS_MAX_SPLIT} domains to resolvers")
    split = {}
    for domain, resolvers in sorted(raw_split.items()):
        dns_name(domain, "A split DNS domain")
        if domain == base or domain.endswith("." + base):
            raise DeploymentError("Split DNS must not override the MagicDNS domain")
        # A route that captures the coordinator's own name can lock clients out once their cached address expires.
        if any(host == domain or host.endswith("." + domain) for host in hosts):
            raise DeploymentError("Split DNS must not capture the coordinator or administration hostname")
        if not resolvers:
            raise DeploymentError("Each split DNS domain requires at least one resolver")
        split[domain] = dns_resolvers(resolvers, "Split DNS resolvers")
    search = dns.get("search_domains", [])
    if not isinstance(search, list) or len(search) > DNS_MAX_SEARCH or len(set(search)) != len(search):
        raise DeploymentError(f"Search domains must be a unique list of at most {DNS_MAX_SEARCH} names")
    for domain in search:
        dns_name(domain, "A search domain")
        if domain == base:
            raise DeploymentError("The MagicDNS domain is always a search domain; do not repeat it")
    records = dns.get("extra_records", [])
    if not isinstance(records, list) or len(records) > DNS_MAX_RECORDS:
        raise DeploymentError(f"Extra records must be a list of at most {DNS_MAX_RECORDS} entries")
    seen, extra = set(), []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"name", "type", "value"} or record["type"] not in ("A", "AAAA"):
            raise DeploymentError("Extra records require exactly name, type and value; clients only process A and AAAA records")
        name = dns_name(record["name"], "An extra record name")
        # Clients only send the MagicDNS domain, split domains and (with override) everything to the local resolver.
        if not name.endswith("." + base):
            raise DeploymentError("Extra records must be inside the MagicDNS domain")
        if name in hosts:
            raise DeploymentError("Extra records must not redefine the coordinator or administration hostname")
        address = dns_address(record["value"], "An extra record value")
        if address.version != (4 if record["type"] == "A" else 6):
            raise DeploymentError("Extra record value does not match its A/AAAA type")
        key = (name, record["type"], str(address))
        if key in seen:
            raise DeploymentError("Extra records contain a duplicate")
        seen.add(key)
        extra.append({"name": name, "type": record["type"], "value": str(address)})
    result = {}
    if override:
        result["override_local_dns"] = True
    for key, value in (("nameservers", nameservers), ("split", split), ("search_domains", list(search)), ("extra_records", extra)):
        if value:
            result[key] = value
    return result


def dns_config(spec):
    """The only source of the coordinator's dns block, shared by preparation and drift detection."""
    custom = spec.get("dns") or {}
    return {"magic_dns": True, "base_domain": spec["dns_base_domain"],
            "override_local_dns": bool(custom.get("override_local_dns", False)),
            "nameservers": {"global": list(custom.get("nameservers", [])),
                            "split": {domain: list(resolvers) for domain, resolvers in custom.get("split", {}).items()}},
            "search_domains": list(custom.get("search_domains", [])),
            "extra_records": [dict(record) for record in custom.get("extra_records", [])]}


def validate_identity(identity):
    if not isinstance(identity, dict) or set(identity) != {"providers", "grants"}:
        raise DeploymentError("Identity requires explicit providers and grants")
    providers = identity["providers"]
    if not isinstance(providers, list) or not 1 <= len(providers) <= 4:
        raise DeploymentError("Identity requires between one and four providers")
    seen = set()
    for provider in providers:
        if not isinstance(provider, dict):
            raise DeploymentError("Identity providers must be objects")
        kind = provider.get("kind")
        if kind not in PROVIDER_KINDS or provider.get("id") != kind or kind in seen:
            raise DeploymentError("Provider IDs and kinds must be unique entra, google, apple or local values")
        seen.add(kind)
        if kind == "local":
            # Local accounts need no upstream registration; the broker keeps them itself.
            if set(provider) - {"id", "kind", "accounts_file"} or provider.get("accounts_file", LOCAL_ACCOUNTS_FILE) != LOCAL_ACCOUNTS_FILE:
                raise DeploymentError("Local accounts take no provider settings")
            continue
        required = {"id", "kind", "client_id"}
        required |= {"issuer", "client_secret_file", "allowed_group_ids"} if kind == "entra" else (
            {"client_secret_file"} if kind == "google" else {"team_id", "key_id", "private_key_file"})
        if set(provider) != required or not isinstance(provider["client_id"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", provider["client_id"]):
            raise DeploymentError("Identity provider fields or client ID are invalid")
        if kind == "entra":
            if not isinstance(provider["issuer"], str) or not re.fullmatch(r"https://login\.microsoftonline\.com/[0-9a-fA-F-]{36}/v2\.0", provider["issuer"]):
                raise DeploymentError("Broker Entra issuer must be a tenant-specific Microsoft v2.0 URL")
            try:
                uuid.UUID(provider["issuer"].split("/")[-2])
                if not isinstance(provider["allowed_group_ids"], list) or not provider["allowed_group_ids"]:
                    raise ValueError("missing groups")
                for group in provider["allowed_group_ids"]:
                    uuid.UUID(group)
            except (ValueError, TypeError, AttributeError) as error:
                raise DeploymentError("Broker Entra enrollment requires explicit group UUIDs") from error
        if kind == "apple" and any(not isinstance(provider[key], str) or not re.fullmatch(r"[A-Z0-9]{10}", provider[key]) for key in ("team_id", "key_id")):
            raise DeploymentError("Apple team and key IDs must contain ten uppercase letters or digits")
        source = provider["private_key_file" if kind == "apple" else "client_secret_file"]
        if not isinstance(source, str) or not Path(source).is_absolute():
            raise DeploymentError("Identity provider credentials require absolute private file paths")
    grants = identity["grants"]
    if not isinstance(grants, list) or len(grants) > 10000:
        raise DeploymentError("Identity grants must be an explicit bounded list")
    granted = set()
    for grant in grants:
        if not isinstance(grant, dict) or set(grant) != {"provider", "subject", "role", "enroll"}:
            raise DeploymentError("Identity grants require provider, subject, role and enroll")
        subject = grant["subject"]
        if not isinstance(grant["provider"], str) or grant["provider"] not in seen or grant["provider"] not in ("google", "apple") or not isinstance(subject, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", subject):
            raise DeploymentError("Social grants must identify a configured provider and its exact stable subject")
        if grant["role"] not in ("", "Covee.Admin", "Covee.Reader") or type(grant["enroll"]) is not bool or (not grant["role"] and not grant["enroll"]):
            raise DeploymentError("A grant must explicitly permit enrollment or a recognized console role")
        key = grant["provider"], subject
        if key in granted:
            raise DeploymentError("Duplicate provider subjects are forbidden")
        granted.add(key)


def runtime_images(metadata):
    images = {**IMAGES, **({"identity": IDENTITY_IMAGE} if metadata["spec"].get("identity") else {})}
    if console_host(metadata["spec"]):
        images["console_node"] = CONSOLE_NODE_IMAGE
    if metadata["spec"].get("gateway"):
        images["gateway"] = GATEWAY_IMAGE
    return images


def identity_files(metadata):
    identity = metadata["spec"].get("identity")
    if not identity:
        return (), ()
    files = (*IDENTITY_CONFIG_FILES, "secrets/identity-signing-key", *("identity-secrets/" + p["id"] + ("-private-key" if p["kind"] == "apple" else "-client-secret") for p in identity["providers"] if p["kind"] != "local"))
    return files, ("identity-secrets",)


def validate_spec(raw, *, lab=False):
    allowed = {"control_host", "admin_host", "public_bind", "public_port", "admin_port", "stun_port",
               "dns_base_domain", "node_expiry", "allowed_group_ids", "oidc", "tls", "identity", "dns", "console_in_network",
               "gateway"}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise DeploymentError("Deployment JSON contains unknown fields")
    spec = {"admin_host": "localhost", "public_bind": "0.0.0.0", "public_port": 443,
            "admin_port": 8444, "stun_port": 3478, "node_expiry": "30d", **raw}
    for key in ("control_host", "admin_host", "dns_base_domain"):
        if key not in spec:
            raise DeploymentError(f"{key} is required")
        hostname(spec[key], lab=lab)
    if spec["control_host"] in ("localhost", spec["admin_host"]) or spec["dns_base_domain"] == spec["control_host"]:
        raise DeploymentError("Control, administration and mesh DNS must have separate names")
    # Devices answer names inside the mesh domain themselves, so they could no longer find the coordinator (Headscale refuses this too).
    if spec["control_host"].endswith("." + spec["dns_base_domain"]):
        raise DeploymentError("The control host must not be inside the mesh DNS domain")
    for key in ("public_port", "admin_port", "stun_port"):
        if type(spec[key]) is not int or not 1 <= spec[key] <= 65535:
            raise DeploymentError(f"{key} must be a valid port")
    if spec["public_port"] == spec["admin_port"]:
        raise DeploymentError("Public and private TCP listeners must use different host ports")
    if not isinstance(spec["public_bind"], str):
        raise DeploymentError("public_bind must be an explicit IP address")
    try:
        ipaddress.ip_address(spec["public_bind"])
    except ValueError as error:
        raise DeploymentError("public_bind must be an explicit IP address") from error
    validate_expiry(spec["node_expiry"])
    if "console_in_network" in spec:
        if type(spec["console_in_network"]) is not bool:
            raise DeploymentError("console_in_network must be true or false")
        if spec["console_in_network"]:
            if not lab and "identity" not in spec:
                raise DeploymentError("The console inside the network needs the identity broker profile")
            hostname(console_host(spec), lab=lab)
            if console_host(spec) in (spec["control_host"], spec["admin_host"]):
                raise DeploymentError("The in-network console needs its own name")
    if "gateway" in spec and type(spec["gateway"]) is not bool:
        raise DeploymentError("gateway must be true or false")
    if "dns" in spec:
        custom = validate_dns(spec["dns"], spec)
        if custom:
            spec["dns"] = custom
        else:
            del spec["dns"]
    if lab:
        if "identity" in spec:
            raise DeploymentError("The disposable token lab cannot enable the identity broker")
        spec["oidc"] = {}
        spec["tls"] = {}
        spec["allowed_group_ids"] = []
        return spec
    if spec["public_port"] != 443:
        raise DeploymentError("Production client ingress must use TCP 443")
    if spec["stun_port"] != 3478:
        raise DeploymentError("The combined production relay profile requires UDP 3478")
    if "identity" in spec:
        if "oidc" in spec or "allowed_group_ids" in spec:
            raise DeploymentError("Identity broker and direct Entra OIDC settings are mutually exclusive")
        validate_identity(spec["identity"])
    else:
        validate_direct_oidc(spec)
    tls = spec.get("tls", {})
    required_tls = {"control_cert_file", "control_key_file"}
    optional_tls = {"admin_cert_file", "admin_key_file"}
    if not isinstance(tls, dict) or not required_tls <= set(tls) or set(tls) - required_tls - optional_tls:
        raise DeploymentError("TLS requires control certificate/key files")
    if bool(tls.get("admin_cert_file")) != bool(tls.get("admin_key_file")):
        raise DeploymentError("Administration certificate/key must be supplied together")
    return spec


def validate_direct_oidc(spec):
    oidc = spec.get("oidc", {})
    required = {"issuer", "coordinator_client_id", "coordinator_client_secret_file",
                "console_client_id", "console_client_secret_file"}
    if not isinstance(oidc, dict) or set(oidc) != required:
        raise DeploymentError("OIDC requires issuer and separate coordinator/console client IDs and secret files")
    if (not isinstance(oidc["issuer"], str) or len(oidc["issuer"]) > 2048 or oidc["issuer"].endswith("/")
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 or ch in "'\"\\$`" for ch in oidc["issuer"])):
        raise DeploymentError("OIDC issuer must be an exact HTTPS URL without a trailing slash")
    issuer = urlsplit(oidc["issuer"])
    if issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password or issuer.query or issuer.fragment:
        raise DeploymentError("OIDC issuer must be a credential-free HTTPS URL")
    if issuer.hostname == "login.microsoftonline.com":
        tenant = issuer.path.strip("/").split("/")
        if len(tenant) != 2 or tenant[1] != "v2.0":
            raise DeploymentError("Entra issuer must be tenant-specific v2.0")
        try:
            uuid.UUID(tenant[0])
        except ValueError as error:
            raise DeploymentError("Entra issuer requires a tenant UUID") from error
    if oidc["coordinator_client_id"] == oidc["console_client_id"]:
        raise DeploymentError("Use separate Entra application registrations for coordinator and console")
    for key in ("coordinator_client_id", "console_client_id"):
        if not isinstance(oidc[key], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", oidc[key]):
            raise DeploymentError("Invalid OIDC client ID")
    groups = spec.get("allowed_group_ids")
    if not isinstance(groups, list) or not groups:
        raise DeploymentError("Explicit allowed_group_ids are required for enrollment")
    try:
        for group in groups:
            uuid.UUID(group)
    except (ValueError, TypeError, AttributeError) as error:
        raise DeploymentError("Enrollment groups must be Entra group UUIDs") from error


def read_source(path, *, secret=False, private=False):
    if not isinstance(path, (str, Path)):
        raise DeploymentError("Source files must be absolute readable regular files")
    source = Path(path)
    if not source.is_absolute() or not source.is_file():
        raise DeploymentError("Source files must be absolute readable regular files")
    if source.stat().st_size > (8192 if secret else 1 << 20):
        raise DeploymentError("Source file exceeds its size limit")
    if (secret or private) and source.stat().st_mode & 0o077:
        raise DeploymentError("Source secret/key permissions must exclude group and other users")
    try:
        content = source.read_bytes()
    except OSError as error:
        raise DeploymentError("Cannot read a required source file") from error
    if secret:
        value = content.removesuffix(b"\n").removesuffix(b"\r") if content.endswith(b"\n") else content
        if not value or value != value.strip() or b"\n" in value or b"\r" in value:
            raise DeploymentError("A credential must contain one nonempty line without surrounding whitespace")
    return content


def cert_pair(cert, key, host):
    run(["openssl", "x509", "-in", cert, "-checkend", "86400", "-noout"])
    host_check = run(["openssl", "x509", "-in", cert, "-checkhost", host, "-noout"])
    # OpenSSL 3.0 reports hostname mismatches on stdout but still exits zero.
    # Require its complete affirmative result; unknown/ambiguous output fails
    # closed without changing OpenSSL's SAN matching or certificate trust rules.
    if host_check.stdout.strip() != f"Hostname {host} does match certificate".encode():
        raise DeploymentError("TLS certificate does not match the configured hostname")
    public_cert = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"]).stdout
    public_key = run(["openssl", "pkey", "-in", key, "-passin", "pass:", "-pubout"]).stdout
    if public_cert != public_key:
        raise DeploymentError("TLS certificate does not match its private key")


def days_left(cert):
    """Whole days until a certificate expires (negative once expired)."""
    end = " ".join(run(["openssl", "x509", "-in", cert, "-enddate", "-noout"]).stdout.decode().strip().removeprefix("notAfter=").split())
    expires = datetime.strptime(end, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def issue_certificate(directory, name, host):
    key, cert = directory / f"{name}.key", directory / f"{name}.crt"
    csr, extensions = directory / f"{name}.csr", directory / f"{name}.extensions"
    run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-subj", f"/CN={host}", "-keyout", key, "-out", csr])
    key.chmod(0o400)
    write_private(extensions, f"subjectAltName=DNS:{host}\nbasicConstraints=critical,CA:FALSE\n"
                  "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
    run(["openssl", "x509", "-req", "-in", csr, "-CA", directory / "internal-ca.crt",
         "-CAkey", directory / "internal-ca.key", "-set_serial", str(secrets.randbits(128) or 1),
         "-days", "90", "-sha256", "-extfile", extensions, "-out", cert])
    cert.chmod(0o400)
    csr.unlink()
    extensions.unlink()
    cert_pair(cert, key, host)


def origin(host, port):
    return "https://" + host + (f":{port}" if port != 443 else "")


def console_host(spec):
    """The console's in-network hostname, or None when it is not served there."""
    return "console." + spec["dns_base_domain"] if spec.get("console_in_network") else None


def cert_covers(cert, host):
    # Some OpenSSL builds exit nonzero on a mismatch, others print it and exit zero.
    result = run(["openssl", "x509", "-in", cert, "-checkhost", host, "-noout"], check=False)
    return result.returncode == 0 and result.stdout.strip() == f"Hostname {host} does match certificate".encode()


def console_grant():
    return {"src": ["autogroup:member"], "dst": [CONSOLE_TAG], "ip": ["tcp:443"]}


def strip_hujson(text):
    """Standard JSON from HuJSON: drop // and /* */ comments and trailing commas."""
    out, i, quoted = [], 0, False
    while i < len(text):
        ch = text[i]
        if quoted:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            out.append(ch)
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise DeploymentError("The persisted policy has an unterminated comment")
            i = end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def with_console_access(policy_text):
    """The policy plus the console's tag owner and its single grant, or None if both are present.

    Members of the network may reach only TCP 443 of the console device; the
    console still requires an administrator's sign-in."""
    try:
        policy = json.loads(strip_hujson(policy_text))
    except ValueError as error:
        raise DeploymentError("The persisted policy could not be read; add the console grant in the console's policy editor") from error
    if not isinstance(policy, dict):
        raise DeploymentError("The persisted policy is not an object")
    owners = policy.setdefault("tagOwners", {})
    grants = policy.setdefault("grants", [])
    if not isinstance(owners, dict) or not isinstance(grants, list):
        raise DeploymentError("The persisted policy has unexpected tagOwners or grants")
    changed = False
    if CONSOLE_TAG not in owners:
        owners[CONSOLE_TAG] = []
        changed = True
    if console_grant() not in grants:
        grants.append(console_grant())
        changed = True
    return json.dumps(policy, indent=2) + "\n" if changed else None


def with_tag_owner(policy_text, tag):
    """The policy with an owner entry for tag, or None if it has one. A device
    cannot join with a tag the policy does not know."""
    try:
        policy = json.loads(strip_hujson(policy_text))
    except ValueError as error:
        raise DeploymentError("The persisted policy could not be read") from error
    owners = policy.setdefault("tagOwners", {}) if isinstance(policy, dict) else None
    if not isinstance(owners, dict):
        raise DeploymentError("The persisted policy has unexpected tagOwners")
    if tag in owners:
        return None
    owners[tag] = []
    return json.dumps(policy, indent=2) + "\n"


def move_accounts(database, old_issuer, new_issuer):
    """File the coordinator's sign-in accounts under a new issuer; returns how many moved.

    Headscale files each account under issuer + "/" + subject. The broker's
    subjects do not depend on its own address, so only that prefix changes,
    and people keep their account and devices."""
    old, new = old_issuer + "/", new_issuer + "/"
    try:
        connection = sqlite3.connect(database)
    except sqlite3.Error as error:
        raise DeploymentError("The coordinator database could not be opened") from error
    try:
        with connection:
            moved = connection.execute("UPDATE users SET provider_identifier = ? || substr(provider_identifier, ?) "
                                       "WHERE substr(provider_identifier, 1, ?) = ?", (new, len(old) + 1, len(old), old)).rowcount
    except sqlite3.Error as error:
        raise DeploymentError("The coordinator's accounts could not be moved to the new name") from error
    finally:
        connection.close()
    return moved


def runtime_env(directory, metadata, images=None):
    spec = metadata["spec"]
    values = {"COVEE_DEPLOY_DIR": str(directory), "COVEE_CONTROL_HOST": spec["control_host"],
              "COVEE_ADMIN_HOST": spec["admin_host"], "COVEE_PUBLIC_BIND": spec["public_bind"],
              "COVEE_PUBLIC_PORT": spec["public_port"], "COVEE_ADMIN_PORT": spec["admin_port"],
              "COVEE_STUN_PORT": spec["stun_port"], "COVEE_UID": metadata["uid"],
              "COVEE_GID": metadata["gid"]}
    if ipaddress.ip_address(spec["public_bind"]).version == 6:
        values["COVEE_PUBLIC_BIND"] = "[" + spec["public_bind"] + "]"
    if console_host(spec):
        values["COVEE_MESH_CONSOLE_HOST"] = console_host(spec)
    for name, ref in (images or runtime_images(metadata)).items():
        values[f"COVEE_{name.upper()}_IMAGE"] = ref
    # Single quotes suppress Compose interpolation. Newlines/quotes are forbidden.
    if any(any(ch in str(value) for ch in "\r\n'$") for value in values.values()):
        raise DeploymentError("Deployment path/values cannot contain quotes, dollar signs or newlines")
    return "".join(f"{key}='{value}'\n" for key, value in values.items())


def downstream_oidc(spec):
    if spec.get("identity"):
        return {"issuer": origin(spec["control_host"], spec["public_port"]) + "/identity",
                "coordinator_client_id": "covee-coordinator", "console_client_id": "covee-console"}, ["covee.enroll"]
    return spec["oidc"], spec["allowed_group_ids"]


def identity_config(spec):
    oidc, _ = downstream_oidc(spec)
    providers = json.loads(json.dumps(spec["identity"]["providers"]))
    for provider in providers:
        if provider["kind"] == "local":
            provider["accounts_file"] = LOCAL_ACCOUNTS_FILE
            continue
        field = "private_key_file" if provider["kind"] == "apple" else "client_secret_file"
        provider[field] = "/run/identity-secrets/" + provider["id"] + ("-private-key" if provider["kind"] == "apple" else "-client-secret")
    return {"issuer": oidc["issuer"], "listen": ":8446", "tls_cert_file": "/run/covee/identity-internal.crt",
            "tls_key_file": "/run/covee/identity-internal.key", "signing_key_file": "/run/secrets/identity-signing-key",
            "clients": [{"id": "covee-coordinator", "secret_file": "/run/secrets/oidc-client-secret",
                         "redirect_uri": origin(spec["control_host"], spec["public_port"]) + "/oidc/callback", "kind": "enrollment"},
                        {"id": "covee-console", "secret_file": "/run/secrets/entra-client-secret",
                         "redirect_uri": origin(spec["admin_host"], spec["admin_port"]) + "/auth/oidc/callback", "kind": "console",
                         **({"extra_redirect_uris": [origin(console_host(spec), 443) + "/auth/oidc/callback"]} if console_host(spec) else {})}],
            "providers": providers, "grants": spec["identity"]["grants"]}


def enrollment_oidc(spec):
    oidc, groups = downstream_oidc(spec)
    config = {"only_start_if_oidc_is_available": True, "issuer": oidc["issuer"],
              "client_id": oidc["coordinator_client_id"], "client_secret_path": "/run/secrets/oidc-client-secret",
              "scope": ["openid", "profile", "email"], "allowed_groups": groups,
              "pkce": {"enabled": True, "method": "S256"}, "use_expiry_from_token": False}
    if spec.get("identity"):
        config["scope"] = ["openid", "profile"]
    return config


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_gateway_dirs(directory):
    for name in (GATEWAY_STATE, GATEWAY_CONFIG):
        path = directory / name
        if not path.exists():
            path.mkdir(mode=0o700)


def prepare(directory, raw, *, lab=False):
    spec = validate_spec(raw, lab=lab)
    if os.getuid() == 0:
        raise DeploymentError("Prepare as a dedicated non-root service account; UID 0 is forbidden")
    directory = directory.absolute()
    if directory.exists() or directory.is_symlink():
        raise DeploymentError("Preparation requires a new directory; existing state is never overwritten")
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=0o700)
    for name in ("secrets", "state", "state/headscale", "state/management"):
        (directory / name).mkdir(mode=0o700)
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-sha256", "-days", "365", "-subj", "/CN=Covee private runtime CA",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", directory / "internal-ca.key", "-out", directory / "internal-ca.crt"])
    for name in ("internal-ca.key", "internal-ca.crt"):
        (directory / name).chmod(0o400)
    issue_certificate(directory, "headscale-internal", "headscale")
    issue_certificate(directory, "management-internal", "management")
    if lab:
        issue_certificate(directory, "ingress-control", spec["control_host"])
    else:
        for field, target in (("control_cert_file", "ingress-control.crt"), ("control_key_file", "ingress-control.key")):
            write_private(directory / target, read_source(spec["tls"][field], private=field.endswith("key_file")))
        cert_pair(directory / "ingress-control.crt", directory / "ingress-control.key", spec["control_host"])
        if console_host(spec) and not cert_covers(directory / "ingress-control.crt", console_host(spec)):
            raise DeploymentError("The public certificate must also name the in-network console host")
    if console_host(spec):
        (directory / CONSOLE_NODE_STATE).mkdir(mode=0o700)
    if spec.get("gateway"):
        create_gateway_dirs(directory)
    if spec["tls"].get("admin_cert_file"):
        for field, target in (("admin_cert_file", "ingress-admin.crt"), ("admin_key_file", "ingress-admin.key")):
            write_private(directory / target, read_source(spec["tls"][field], private=field.endswith("key_file")))
        cert_pair(directory / "ingress-admin.crt", directory / "ingress-admin.key", spec["admin_host"])
    else:
        issue_certificate(directory, "ingress-admin", spec["admin_host"])
    if spec.get("identity"):
        (directory / "identity-secrets").mkdir(mode=0o700)
        (directory / "state/identity").mkdir(mode=0o700)
        issue_certificate(directory, "identity-internal", "identity")
        write_private(directory / "identity-trust.pem", (directory / "internal-ca.crt").read_bytes() + (directory / "ingress-control.crt").read_bytes())
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", directory / "secrets/identity-signing-key"], timeout=120)
        (directory / "secrets/identity-signing-key").chmod(0o400)
        for provider in spec["identity"]["providers"]:
            if provider["kind"] == "local":
                continue
            apple = provider["kind"] == "apple"
            field = "private_key_file" if apple else "client_secret_file"
            target = directory / "identity-secrets" / (provider["id"] + ("-private-key" if apple else "-client-secret"))
            write_private(target, read_source(provider[field], secret=not apple, private=apple))
            if apple:
                key = run(["openssl", "pkey", "-in", target, "-passin", "pass:", "-text", "-noout"]).stdout
                if b"ASN1 OID: prime256v1" not in key:
                    raise DeploymentError("Apple signing keys must use P-256")
        write_private(directory / "identity.json", json.dumps(identity_config(spec), indent=2) + "\n")
    for name in SECRET_FILES:
        value = secrets.token_urlsafe(48) if name == "admin-token" and lab else ""
        if spec.get("identity") and name in ("oidc-client-secret", "entra-client-secret"):
            value = secrets.token_urlsafe(48)
        elif name == "oidc-client-secret" and not lab:
            value = read_source(spec["oidc"]["coordinator_client_secret_file"], secret=True)
        elif name == "entra-client-secret" and not lab:
            value = read_source(spec["oidc"]["console_client_secret_file"], secret=True)
        write_private(directory / "secrets" / name, value)
    headscale = {"server_url": origin(spec["control_host"], spec["public_port"]), "listen_addr": "0.0.0.0:8443",
                 "tls_cert_path": "/run/covee/headscale-internal.crt", "tls_key_path": "/run/covee/headscale-internal.key",
                 "metrics_listen_addr": "127.0.0.1:9090", "grpc_listen_addr": "127.0.0.1:50443", "grpc_allow_insecure": False,
                 "noise": {"private_key_path": "/var/lib/headscale/noise_private.key"},
                 "prefixes": {"v4": "100.64.0.0/24" if lab else "100.64.0.0/10", "v6": "fd7a:115c:a1e0::/48", "allocation": "sequential"},
                 "derp": {"server": {"enabled": True, "region_id": 999, "region_code": "owned", "region_name": "Covee owned relay",
                                     "verify_clients": True, "stun_listen_addr": "0.0.0.0:3478",
                                     "private_key_path": "/var/lib/headscale/derp_private.key", "automatically_add_embedded_derp_region": True},
                          "urls": [], "paths": [], "auto_update_enabled": False},
                 "database": {"type": "sqlite", "sqlite": {"path": "/var/lib/headscale/db.sqlite", "write_ahead_log": True}},
                 "node": {"expiry": spec["node_expiry"]}, "policy": {"mode": "database"},
                 "dns": dns_config(spec),
                 "unix_socket": "/var/run/headscale/headscale.sock", "unix_socket_permission": "0700",
                 "log": {"format": "json", "level": "warn"}, "logtail": {"enabled": False}, "disable_check_updates": True}
    if not lab:
        headscale["oidc"] = enrollment_oidc(spec)
    write_private(directory / "headscale.yaml", json.dumps(headscale, indent=2) + "\n")
    write_private(directory / "initial-policy.hujson", '{"grants": [], "ssh": []}\n')
    management = {"COVEE_LISTEN": ":8445", "COVEE_PUBLIC_URL": origin(spec["admin_host"], spec["admin_port"]),
                  "COVEE_HEADSCALE_URL": "https://headscale:8443", "COVEE_HEADSCALE_CA_FILE": "/run/covee/internal-ca.crt",
                  "COVEE_TLS_CERT_FILE": "/run/covee/management-internal.crt", "COVEE_TLS_KEY_FILE": "/run/covee/management-internal.key",
                  "COVEE_HEADSCALE_API_KEY_FILE": "/run/secrets/headscale-api-key", "COVEE_DATA_DIR": "/data",
                  "COVEE_AUTH_MODE": "token" if lab else "oidc"}
    if lab:
        management["COVEE_ADMIN_TOKEN_FILE"] = "/run/secrets/admin-token"
    else:
        oidc, _ = downstream_oidc(spec)
        management.update({"COVEE_OIDC_ISSUER": oidc["issuer"], "COVEE_OIDC_CLIENT_ID": oidc["console_client_id"],
                           "COVEE_OIDC_CLIENT_SECRET_FILE": "/run/secrets/entra-client-secret"})
        if spec.get("identity"):
            management.update(COVEE_OIDC_LABEL="Continue to sign in", SSL_CERT_DIR="/run/covee/identity-ca")
        if console_host(spec):
            management["COVEE_ADDITIONAL_ORIGINS"] = origin(console_host(spec), 443)
    write_private(directory / "management.env", "".join(f"{key}={value}\n" for key, value in management.items()))
    # Keep source credential paths out of the portable prepared metadata.
    stored = json.loads(json.dumps(spec))
    for key in ("coordinator_client_secret_file", "console_client_secret_file"):
        if key in stored.get("oidc", {}):
            del stored["oidc"][key]
    if stored.get("identity"):
        # Preserve only fixed container paths, never operator source paths.
        stored["identity"]["providers"] = identity_config(spec)["providers"]
    stored["tls"] = {}
    metadata = {"format": 1, "lab": lab, "uid": os.getuid(), "gid": os.getgid(), "spec": stored}
    write_private(directory / "deployment.json", json.dumps(metadata, indent=2) + "\n")
    write_private(directory / "runtime.env", runtime_env(directory, metadata))
    validate(directory)
    return directory


def validate(directory, *, production=False):
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077:
        raise DeploymentError("Prepared directory must be a private real directory")
    metadata = load_json(directory / "deployment.json")
    if metadata.get("format") != 1 or metadata.get("uid") != os.getuid() or metadata.get("gid") != os.getgid() or os.getuid() == 0:
        raise DeploymentError("Prepared runtime must be owned and operated by its non-root service account")
    if production and metadata.get("lab") is not False:
        raise DeploymentError("Disposable lab configuration cannot be deployed as production")
    extra_files, extra_dirs = identity_files(metadata)
    for name in (*CONFIG_FILES, "deployment.json", "runtime.env", *("secrets/" + name for name in SECRET_FILES), *extra_files):
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != metadata["uid"] or path.stat().st_mode & 0o077:
            raise DeploymentError("Prepared files must be private regular files owned by the service account")
    for name in ("secrets", "state", "state/headscale", "state/management", *extra_dirs):
        path = directory / name
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != metadata["uid"] or path.stat().st_mode & 0o077:
            raise DeploymentError("State directories must be private and owned by the service account")
    spec = metadata["spec"]
    reconstructed = json.loads(json.dumps(spec))
    if not metadata["lab"]:
        if not spec.get("identity"):
            reconstructed["oidc"].update(coordinator_client_secret_file="/unused/coordinator", console_client_secret_file="/unused/console")
        reconstructed["tls"] = {"control_cert_file": "/unused/cert", "control_key_file": "/unused/key"}
    validate_spec(reconstructed, lab=metadata["lab"])
    config = load_json(directory / "headscale.yaml")
    if load_json(directory / "initial-policy.hujson") != {"grants": [], "ssh": []}:
        raise DeploymentError("Bootstrap policy must retain its explicit default deny; edit the persisted policy through administration")
    critical = {"server_url": origin(spec["control_host"], spec["public_port"]), "listen_addr": "0.0.0.0:8443",
                "tls_cert_path": "/run/covee/headscale-internal.crt", "tls_key_path": "/run/covee/headscale-internal.key",
                "noise": {"private_key_path": "/var/lib/headscale/noise_private.key"},
                "database": {"type": "sqlite", "sqlite": {"path": "/var/lib/headscale/db.sqlite", "write_ahead_log": True}},
                "policy": {"mode": "database"}, "node": {"expiry": spec["node_expiry"]},
                "unix_socket": "/var/run/headscale/headscale.sock", "unix_socket_permission": "0700"}
    if any(config.get(key) != value for key, value in critical.items()):
        raise DeploymentError("Prepared coordinator origin, TLS, storage, policy or lifetime differs from its deployment contract")
    if config.get("dns") != dns_config(spec):
        raise DeploymentError("Prepared coordinator DNS differs from the DNS settings recorded for this deployment")
    expected_env = {"COVEE_LISTEN": ":8445", "COVEE_PUBLIC_URL": origin(spec["admin_host"], spec["admin_port"]),
                    "COVEE_HEADSCALE_URL": "https://headscale:8443", "COVEE_HEADSCALE_CA_FILE": "/run/covee/internal-ca.crt",
                    "COVEE_TLS_CERT_FILE": "/run/covee/management-internal.crt", "COVEE_TLS_KEY_FILE": "/run/covee/management-internal.key",
                    "COVEE_HEADSCALE_API_KEY_FILE": "/run/secrets/headscale-api-key", "COVEE_DATA_DIR": "/data",
                    "COVEE_AUTH_MODE": "token" if metadata["lab"] else "oidc"}
    if metadata["lab"]:
        expected_env["COVEE_ADMIN_TOKEN_FILE"] = "/run/secrets/admin-token"
    else:
        expected_oidc = enrollment_oidc(spec)
        if config.get("oidc") != expected_oidc:
            raise DeploymentError("Prepared enrollment identity differs from its restricted OIDC contract")
        oidc, _ = downstream_oidc(spec)
        expected_env.update(COVEE_OIDC_ISSUER=oidc["issuer"], COVEE_OIDC_CLIENT_ID=oidc["console_client_id"],
                            COVEE_OIDC_CLIENT_SECRET_FILE="/run/secrets/entra-client-secret")
        if console_host(spec):
            expected_env["COVEE_ADDITIONAL_ORIGINS"] = origin(console_host(spec), 443)
        if spec.get("identity"):
            expected_env.update(COVEE_OIDC_LABEL="Continue to sign in", SSL_CERT_DIR="/run/covee/identity-ca")
            if load_json(directory / "identity.json") != identity_config(spec):
                raise DeploymentError("Prepared identity broker differs from its explicit provider/client/grant contract")
            if (directory / "identity-trust.pem").read_bytes() != (directory / "internal-ca.crt").read_bytes() + (directory / "ingress-control.crt").read_bytes():
                raise DeploymentError("Prepared identity trust differs from runtime and selected ingress certificates")
            expected_secrets = {Path(path).name for path in extra_files if path.startswith("identity-secrets/")}
            if {path.name for path in (directory / "identity-secrets").iterdir()} != expected_secrets:
                raise DeploymentError("Prepared identity secrets differ from the configured providers")
            signing_key = run(["openssl", "pkey", "-in", directory / "secrets/identity-signing-key", "-passin", "pass:", "-text", "-noout"]).stdout
            if not re.search(rb"Private-Key: \(3072 bit", signing_key):
                raise DeploymentError("Identity signing key must be RSA 3072")
            for provider in spec["identity"]["providers"]:
                if provider["kind"] == "local":
                    continue
                apple = provider["kind"] == "apple"
                source = directory / "identity-secrets" / (provider["id"] + ("-private-key" if apple else "-client-secret"))
                read_source(source, secret=not apple, private=apple)
                if apple and b"ASN1 OID: prime256v1" not in run(["openssl", "pkey", "-in", source, "-passin", "pass:", "-text", "-noout"]).stdout:
                    raise DeploymentError("Apple signing keys must use P-256")
    actual_env = {}
    for line in (directory / "management.env").read_text().splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in actual_env:
            raise DeploymentError("Prepared management environment contains invalid or duplicate fields")
        actual_env[key] = value
    if actual_env != expected_env:
        raise DeploymentError("Prepared management identity, origin, TLS or credential sources differ from the deployment contract")
    actual_runtime = {}
    for line in (directory / "runtime.env").read_text().splitlines():
        match = re.fullmatch(r"(COVEE_[A-Z_]+)='([^'\r\n$]*)'", line)
        if not match or match[1] in actual_runtime:
            raise DeploymentError("Prepared runtime environment contains invalid or duplicate fields")
        actual_runtime[match[1]] = match[2]
    images = runtime_images(metadata)
    selected_images = {name: actual_runtime.get(f"COVEE_{name.upper()}_IMAGE", "") for name in images}
    if any(value != images[name] and not re.fullmatch(r"sha256:[a-f0-9]{64}", value) for name, value in selected_images.items()):
        raise DeploymentError("Runtime images must be expected local builds or immutable image IDs")
    if (directory / "runtime.env").read_text() != runtime_env(directory, metadata, selected_images):
        raise DeploymentError("Prepared runtime paths, ownership or network settings differ from metadata")
    if config.get("grpc_allow_insecure") or config.get("metrics_listen_addr") != "127.0.0.1:9090" or config.get("grpc_listen_addr") != "127.0.0.1:50443":
        raise DeploymentError("Administrative and diagnostic listeners must remain private")
    if config.get("derp", {}).get("server", {}).get("verify_clients") is not True or config.get("logtail", {}).get("enabled") is not False:
        raise DeploymentError("Relay verification and disabled log upload are required")
    if config.get("database", {}).get("type") != "sqlite":
        raise DeploymentError("Persistent SQLite and deliberate nonzero node expiration are required")
    validate_expiry(config.get("node", {}).get("expiry"))
    if production:
        oidc = config.get("oidc", {})
        if oidc.get("only_start_if_oidc_is_available") is not True or oidc.get("pkce") != {"enabled": True, "method": "S256"} or not oidc.get("allowed_groups"):
            raise DeploymentError("Production enrollment requires restricted, fail-closed OIDC with PKCE")
        env = (directory / "management.env").read_text()
        if "COVEE_AUTH_MODE=oidc\n" not in env or "COVEE_ADMIN_TOKEN" in env or "COVEE_ALLOW_HTTP=true" in env:
            raise DeploymentError("Production console must use OIDC without token bypass")
        for name in ("oidc-client-secret", "entra-client-secret"):
            read_source(str(directory / "secrets" / name), secret=True)
    cert_pair(directory / "ingress-control.crt", directory / "ingress-control.key", metadata["spec"]["control_host"])
    if console_host(spec) and not metadata["lab"] and not cert_covers(directory / "ingress-control.crt", console_host(spec)):
        raise DeploymentError("The public certificate does not name the in-network console host")
    if console_host(spec):
        path = directory / CONSOLE_NODE_STATE
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != metadata["uid"] or path.stat().st_mode & 0o077:
            raise DeploymentError("The console node's state folder must be private and owned by the service account")
    if spec.get("gateway"):
        for name in (GATEWAY_STATE, GATEWAY_CONFIG):
            path = directory / name
            if path.is_symlink() or not path.is_dir() or path.stat().st_uid != metadata["uid"] or path.stat().st_mode & 0o077:
                raise DeploymentError("The gateway's folders must be private and owned by the service account")
    cert_pair(directory / "ingress-admin.crt", directory / "ingress-admin.key", metadata["spec"]["admin_host"])
    internal = [("headscale-internal", "headscale"), ("management-internal", "management")]
    if spec.get("identity"):
        internal.append(("identity-internal", "identity"))
    for name, host in internal:
        cert_pair(directory / f"{name}.crt", directory / f"{name}.key", host)
        run(["openssl", "verify", "-CAfile", directory / "internal-ca.crt", "-verify_hostname", host, directory / f"{name}.crt"])
    return metadata


class Runtime:
    def __init__(self, directory, *, override=None):
        self.directory = directory.absolute()
        self.project = "covee-portable-" + hashlib.sha256(str(self.directory).encode()).hexdigest()[:12]
        self.base = ["docker", "compose", "--project-name", self.project, "--env-file", self.directory / "runtime.env", "--file", COMPOSE]
        spec = load_json(self.directory / "deployment.json")["spec"]
        self.identity = bool(spec.get("identity"))
        self.console = console_host(spec)
        self.gateway = bool(spec.get("gateway"))
        if self.identity:
            self.base += ["--file", IDENTITY_COMPOSE]
        if self.console:
            self.base += ["--file", CONSOLE_COMPOSE]
        if self.gateway:
            self.base += ["--file", GATEWAY_COMPOSE]
        if override:
            self.base += ["--file", override]

    def compose(self, *args, **kwargs):
        # Shell variables otherwise override --env-file, including bind paths,
        # image references and published ports for a different deployment.
        kwargs.setdefault("env", {key: value for key, value in os.environ.items() if not key.startswith("COVEE_")})
        return run(self.base + list(args), **kwargs)

    def control(self, *args, **kwargs):
        return self.compose("exec", "-T", "headscale", "/headscale", *args, **kwargs)

    def acquire_lock(self):
        fd = os.open(self.directory / ".operation.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise DeploymentError("Runtime operation lock must be a private operator-owned regular file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, DeploymentError) as error:
            os.close(fd)
            raise DeploymentError("Another operation is active or the runtime operation lock is unsafe") from error
        return os.fdopen(fd, "r+")

    def wait(self, service, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.compose("ps", "--format", "json", service, check=False)
            try:
                try:
                    parsed = json.loads(result.stdout)
                    entries = parsed if isinstance(parsed, list) else [parsed]
                except ValueError:
                    entries = [json.loads(line) for line in result.stdout.splitlines() if line]
                if entries and entries[0].get("Health") == "healthy":
                    return
            except ValueError:
                pass
            time.sleep(1)
        raise DeploymentError(f"Timed out waiting for {service} health")

    def bootstrap(self):
        # Re-check policy before reconnecting a previously published ingress.
        self.compose("stop", "ingress", "management", *( ["headscale"] if self.identity else []), timeout=60)
        marker = self.directory / "state/headscale/.policy-initialized"
        database = self.directory / "state/headscale/db.sqlite"
        if marker.exists() and not database.is_file():
            raise DeploymentError("Initialized coordinator database is missing; restore it before startup")
        if self.identity:
            # Discovery must be reachable before Headscale can start. This
            # gateway configuration serves only identity routes: control and
            # administration remain denied until persisted policy is checked.
            self.compose("--file", IDENTITY_BOOTSTRAP_COMPOSE, "up", "--detach", "--no-deps", "--force-recreate", "identity", "ingress", timeout=120)
            self.wait("identity")
        self.compose("up", "--detach", "headscale", timeout=120)
        self.wait("headscale")
        if not marker.exists():
            self.control("policy", "set", "--file", "/etc/headscale/initial-policy.hujson")
        policy = self.control("policy", "get").stdout.strip()
        if not policy or policy == b"null":
            raise DeploymentError("Coordinator has no explicit persisted policy; public ingress remains stopped")
        if not marker.exists():
            write_private(marker, "explicit policy verified\n", mode=0o600)
        # A stopped installation may retain an expired file. Never infer
        # validity from its existence; issue a fresh bounded credential.
        self.rotate_api_key(recreate=False)

    def rotate_api_key(self, *, recreate=True):
        result = self.control("apikeys", "create", "--expiration", "24h", "--output", "json")
        try:
            value = json.loads(result.stdout)
            if isinstance(value, dict):
                value = value.get("apiKey") or value.get("key")
            if not isinstance(value, str) or not value.startswith("hskey-api-") or any(c.isspace() for c in value):
                raise ValueError("invalid credential")
        except (ValueError, TypeError) as error:
            raise DeploymentError("Coordinator returned an invalid API credential") from error
        replace_private(self.directory / "secrets/headscale-api-key", value)
        if recreate:
            self.compose("up", "--detach", "--force-recreate", "management", timeout=120)

    def update_identity_grants(self, grants):
        metadata = validate(self.directory, production=True)
        if not self.identity:
            raise DeploymentError("Social grants require the optional identity broker profile")
        metadata["spec"]["identity"]["grants"] = grants
        validate_identity(metadata["spec"]["identity"])
        # Both private files must agree before restart; any interrupted update
        # is detected by validate rather than silently selecting one copy.
        replace_private(self.directory / "identity.json", json.dumps(identity_config(metadata["spec"]), indent=2) + "\n")
        replace_private(self.directory / "deployment.json", json.dumps(metadata, indent=2) + "\n")
        validate(self.directory, production=True)
        self.compose("up", "--detach", "--no-deps", "--force-recreate", "identity", timeout=120)
        self.wait("identity")

    def update_identity_providers(self, providers):
        """Replace the broker's complete upstream provider list in place.

        Only the broker restarts: the coordinator, console and enrolled devices
        keep running. Existing grants must still name enabled providers. The
        broker issuer and signing key are unchanged, so subjects of providers
        that stay enabled keep their access."""
        metadata = validate(self.directory, production=True)
        if not self.identity:
            raise DeploymentError("Provider changes require the optional identity broker profile")
        spec = metadata["spec"]
        identity = {"providers": providers, "grants": spec["identity"]["grants"]}
        try:
            validate_identity(identity)
        except DeploymentError as error:
            if isinstance(providers, list) and any(isinstance(g, dict) and g.get("provider") not in {p.get("id") for p in providers if isinstance(p, dict)}
                                                   for g in spec["identity"]["grants"]):
                raise DeploymentError("Remove the grants of a provider before disabling it") from error
            raise
        names = {p["id"]: p["id"] + ("-private-key" if p["kind"] == "apple" else "-client-secret") for p in providers if p["kind"] != "local"}
        staged = {}
        self.ensure_identity_state()
        for provider in providers:
            if provider["kind"] == "local":
                continue
            apple = provider["kind"] == "apple"
            staged[names[provider["id"]]] = read_source(provider["private_key_file" if apple else "client_secret_file"], secret=not apple, private=apple)
        secrets_dir = self.directory / "identity-secrets"
        paths = [self.directory / "identity.json", self.directory / "deployment.json"]
        previous_files = {path: path.read_bytes() for path in paths}
        previous_secrets = {path.name: path.read_bytes() for path in secrets_dir.iterdir()}
        spec["identity"] = {"providers": providers, "grants": identity["grants"]}
        config = identity_config(spec)
        # Like prepare(), keep only fixed container paths in the portable metadata.
        spec["identity"]["providers"] = config["providers"]
        try:
            for name, value in staged.items():
                replace_private(secrets_dir / name, value)
            for name in set(previous_secrets) - set(staged):
                (secrets_dir / name).unlink()
            replace_private(paths[0], json.dumps(config, indent=2) + "\n")
            replace_private(paths[1], json.dumps(metadata, indent=2) + "\n")
            validate(self.directory, production=True)
            self.compose("up", "--detach", "--no-deps", "--force-recreate", "identity", timeout=120)
            self.wait("identity")
        except DeploymentError:
            for path in secrets_dir.iterdir():
                if path.name not in previous_secrets:
                    path.unlink()
            for name, value in previous_secrets.items():
                replace_private(secrets_dir / name, value)
            for path, value in previous_files.items():
                replace_private(path, value)
            try:
                self.compose("up", "--detach", "--no-deps", "--force-recreate", "identity", timeout=120)
                self.wait("identity")
            except DeploymentError:
                pass
            raise DeploymentError("Provider update failed; the previous providers were restored. Check the runtime with status before relying on it")

    def renew_certificates(self, cert=None, key=None):
        """Optionally install a new public certificate, and reissue the 90-day internal certificates.

        Deliberately does not require validate() first: it refuses certificates
        that expire within a day, which is exactly when renewal is needed. The
        complete result is validated before restart, and any failure restores
        every previous file."""
        directory = self.directory
        metadata = load_json(directory / "deployment.json")
        if metadata.get("lab") is not False or metadata.get("format") != 1:
            raise DeploymentError("Certificate renewal applies to prepared production runtimes")
        spec = metadata["spec"]
        if bool(cert) != bool(key):
            raise DeploymentError("A new public certificate needs both --cert and --key")
        ca_days = days_left(directory / "internal-ca.crt")
        if ca_days < 30:
            raise DeploymentError("The runtime's internal CA expires within 30 days; it must be rotated, which renewal cannot do")
        public = None
        if cert:
            cert_pair(Path(cert), Path(key), spec["control_host"])
            public = read_source(cert), read_source(key, private=True)
        internal = [("headscale-internal", "headscale"), ("management-internal", "management")]
        if spec.get("identity"):
            internal.append(("identity-internal", "identity"))
        admin_internal = run(["openssl", "verify", "-CAfile", directory / "internal-ca.crt", directory / "ingress-admin.crt"], check=False).returncode == 0
        if admin_internal:
            internal.append(("ingress-admin", spec["admin_host"]))
        names = [f"{name}.{ext}" for name, _ in internal for ext in ("crt", "key")]
        if public:
            names += ["ingress-control.crt", "ingress-control.key"]
        if spec.get("identity"):
            names.append("identity-trust.pem")
        previous = {name: (directory / name).read_bytes() for name in names}
        running = bool(self.compose("ps", "--quiet", "headscale").stdout.strip())
        try:
            if public:
                replace_private(directory / "ingress-control.crt", public[0])
                replace_private(directory / "ingress-control.key", public[1])
            for name, host in internal:
                for ext in ("crt", "key"):
                    (directory / f"{name}.renew.{ext}").unlink(missing_ok=True)
                issue_certificate(directory, f"{name}.renew", host)
                for ext in ("key", "crt"):
                    os.replace(directory / f"{name}.renew.{ext}", directory / f"{name}.{ext}")
            if spec.get("identity"):
                replace_private(directory / "identity-trust.pem", (directory / "internal-ca.crt").read_bytes() + (directory / "ingress-control.crt").read_bytes())
            validate(directory, production=True)
            if running:
                # Every service reads its certificates and trust only at startup.
                self.compose("stop", "ingress", "management", "headscale", timeout=60)
                self.start()
        except DeploymentError:
            for name, value in previous.items():
                replace_private(directory / name, value)
            for name, _ in internal:
                for ext in ("crt", "key"):
                    (directory / f"{name}.renew.{ext}").unlink(missing_ok=True)
            try:
                if running:
                    self.start()
            except DeploymentError:
                pass
            raise DeploymentError("Certificate renewal failed; the previous certificates were restored. Check the runtime with status before relying on it")
        return {"public_days_left": days_left(directory / "ingress-control.crt"), "internal_days_left": days_left(directory / "headscale-internal.crt"),
                "internal_ca_days_left": ca_days, "admin_certificate": "renewed" if admin_internal else "operator supplied, not changed",
                "restarted": running}

    def local_accounts(self, action, *, email=None, name=None, role=None, enroll=None, expires=None):
        """Administer local Covee accounts through the running broker's own command."""
        validate(self.directory, production=True)
        providers = load_json(self.directory / "deployment.json")["spec"].get("identity", {}).get("providers", [])
        if not any(p.get("kind") == "local" for p in providers):
            raise DeploymentError("Local accounts are not enabled on this runtime")
        if action not in ("invite", "reset", "update", "remove", "list"):
            raise DeploymentError("Unknown local account action")
        args = ["accounts", action]
        if action != "list":
            if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^@\s\x00-\x1f]{1,64}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", email.lower()):
                raise DeploymentError("A valid email address is required")
            args += ["--email", email.lower()]
        if action == "invite":
            if not isinstance(name, str) or not 1 <= len(name) <= 100 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                raise DeploymentError("A name of 1 to 100 printable characters is required")
            args += ["--name", name]
        if action in ("invite", "update"):
            if role is not None:
                if role not in ("admin", "reader", "none"):
                    raise DeploymentError("Role must be admin, reader or none")
                args += ["--role", role]
            if enroll is not None:
                args += ["--enroll", "true" if enroll else "false"]
        if action in ("invite", "reset"):
            if not re.fullmatch(r"[1-9][0-9]{0,2}h", expires or "") or not 1 <= int(expires[:-1]) <= 336:
                raise DeploymentError("Invite expiry must be between 1h and 336h")
            args += ["--expires", expires]
        result = self.compose("exec", "-T", "identity", "/covee-identity", *args, check=False)
        try:
            reply_ = json.loads(result.stdout)
        except ValueError as error:
            raise DeploymentError("The sign-in service returned an unreadable answer") from error
        if result.returncode or not isinstance(reply_, dict) or "error" in reply_:
            raise DeploymentError("Local account change refused: " + str(reply_.get("error", "unknown error") if isinstance(reply_, dict) else "unknown error")[:200])
        return reply_

    def create_device_key(self, tags, *, expiration="24h", reusable=False, ephemeral=False):
        """Create a tag-owned enrollment key for a device that cannot sign in itself."""
        validate(self.directory, production=True)
        if not isinstance(tags, list) or not 1 <= len(tags) <= 8 or len(set(tags)) != len(tags) or \
                any(not isinstance(t, str) or not re.fullmatch(r"tag:[a-z0-9](?:[a-z0-9-]{0,62})", t) for t in tags):
            raise DeploymentError("Device keys need 1 to 8 distinct tags such as tag:server")
        match = re.fullmatch(r"([1-9][0-9]{0,3})(m|h|d)", expiration or "")
        minutes = int(match[1]) * {"m": 1, "h": 60, "d": 1440}[match[2]] if match else 0
        if not 5 <= minutes <= 90 * 1440:
            raise DeploymentError("Device key expiration must be between 5 minutes and 90 days, such as 30m, 24h or 7d")
        args = ["preauthkeys", "create", "--tags", ",".join(tags), "--expiration", expiration, "--output", "json"]
        if reusable:
            args.append("--reusable")
        if ephemeral:
            args.append("--ephemeral")
        result = self.control(*args)
        try:
            created = json.loads(result.stdout)
            key = created.get("key")
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,200}", key):
                raise ValueError("invalid key")
        except (ValueError, AttributeError) as error:
            raise DeploymentError("Coordinator returned an invalid device key") from error
        expires = created.get("expiration")
        if isinstance(expires, dict) and isinstance(expires.get("seconds"), int):
            expires = datetime.fromtimestamp(expires["seconds"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"key": key, "expiration": expires, "tags": tags, "reusable": reusable, "ephemeral": ephemeral}

    def update_dns(self, dns, *, coordinator_only=False):
        """Replace the complete custom DNS settings; returns whether a running coordinator was restarted.

        coordinator_only restarts just the coordinator, for a runtime whose
        persisted policy and API key are already in place: the console, the
        sign-in service and their sessions keep running."""
        lab = load_json(self.directory / "deployment.json").get("lab") is True
        metadata = validate(self.directory, production=not lab)
        spec = metadata["spec"]
        custom = validate_dns(dns, spec)
        if custom:
            spec["dns"] = custom
        else:
            spec.pop("dns", None)
        config_path, metadata_path = self.directory / "headscale.yaml", self.directory / "deployment.json"
        previous = config_path.read_bytes(), metadata_path.read_bytes()
        config = load_json(config_path)
        config["dns"] = dns_config(spec)
        # Both private files must agree before restart; any interrupted update
        # is detected by validate rather than silently selecting one copy.
        replace_private(config_path, json.dumps(config, indent=2) + "\n")
        replace_private(metadata_path, json.dumps(metadata, indent=2) + "\n")
        running = False
        try:
            validate(self.directory, production=not lab)
            running = bool(self.compose("ps", "--quiet", "headscale").stdout.strip())
            if running and coordinator_only:
                # The coordinator reads its settings only at start; the policy is already persisted.
                self.compose("up", "--detach", "--no-deps", "--force-recreate", "headscale", timeout=120)
                self.wait("headscale")
            elif running:
                # Compose does not notice a changed bind-mounted file, so the coordinator must be stopped
                # for start() to read it, and start() keeps the persisted-policy gate before ingress returns.
                self.compose("stop", "ingress", "management", "headscale", timeout=60)
                self.start()
            return running
        except DeploymentError:
            replace_private(config_path, previous[0])
            replace_private(metadata_path, previous[1])
            try:
                if running:
                    self.start()
            except DeploymentError:
                pass
            raise DeploymentError("DNS update failed; the previous DNS settings were restored. Check the runtime with status before relying on it")

    def ensure_identity_state(self):
        """Runtimes prepared before local accounts existed lack the broker's state folder."""
        if self.identity:
            state = self.directory / "state/identity"
            if not state.exists():
                state.mkdir(mode=0o700)
            if state.is_symlink() or not state.is_dir() or state.stat().st_mode & 0o077 or state.stat().st_uid != os.getuid():
                raise DeploymentError("The broker's state folder must be a private directory owned by the service account")

    def start(self):
        self.ensure_identity_state()
        self.pin_images()
        self.bootstrap()
        self.compose("up", "--detach", "--force-recreate", "management", timeout=120)
        if self.identity:
            self.compose("up", "--detach", "--force-recreate", "ingress", timeout=120)
        if self.console:
            self.prepare_console_node()
        if self.gateway:
            self.prepare_gateway()
        self.compose("up", "--detach", timeout=120)
        if self.console:
            self.finish_console_node()
        if self.gateway:
            self.finish_gateway()

    def prepare_console_node(self):
        """Allow members to reach the console device, and give a new device its one-time key."""
        state = self.directory / CONSOLE_NODE_STATE
        if state.is_symlink() or not state.is_dir() or state.stat().st_mode & 0o077 or state.stat().st_uid != os.getuid():
            raise DeploymentError("The console node's state folder must be a private directory owned by the service account")
        merged = with_console_access(self.control("policy", "get").stdout.decode())
        if merged:
            self.control("policy", "check", "--file", "/dev/stdin", data=merged.encode())
            self.control("policy", "set", "--file", "/dev/stdin", data=merged.encode())
        if (state / CONSOLE_NODE_IDENTITY).exists():
            return
        # A device that lost its identity would otherwise come back as console-1.
        self.delete_tagged_nodes(CONSOLE_TAG, "console")
        key = self.create_device_key([CONSOLE_TAG], expiration="1h")
        replace_private(state / CONSOLE_JOIN_KEY, key["key"] + "\n", mode=0o600)

    def finish_console_node(self):
        """Wait for the console device; its join key is removed once it has joined."""
        try:
            self.wait("console-node", timeout=90)
        except DeploymentError:
            print("The in-network console did not connect yet; check it with `docker compose logs console-node`.", flush=True)
            return
        (self.directory / CONSOLE_NODE_STATE / CONSOLE_JOIN_KEY).unlink(missing_ok=True)

    def prepare_gateway(self):
        """Let the gateway's tag exist, and give a new gateway its one-time key.

        Which routes it offers, who may use them and their approval are the
        management service's (the console's Gateway page)."""
        for name in (GATEWAY_STATE, GATEWAY_CONFIG):
            path = self.directory / name
            if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid():
                raise DeploymentError("The gateway's folders must be private directories owned by the service account")
        merged = with_tag_owner(self.control("policy", "get").stdout.decode(), GATEWAY_TAG)
        if merged:
            self.control("policy", "check", "--file", "/dev/stdin", data=merged.encode())
            self.control("policy", "set", "--file", "/dev/stdin", data=merged.encode())
        state = self.directory / GATEWAY_STATE
        if (state / CONSOLE_NODE_IDENTITY).exists():
            return
        self.delete_tagged_nodes(GATEWAY_TAG, "gateway")
        key = self.create_device_key([GATEWAY_TAG], expiration="1h")
        replace_private(state / CONSOLE_JOIN_KEY, key["key"] + "\n", mode=0o600)

    def finish_gateway(self):
        """Wait for the gateway; its join key is removed once it has joined."""
        try:
            self.wait("gateway", timeout=90)
        except DeploymentError:
            print("The gateway did not connect yet; check it with `docker compose logs gateway`.", flush=True)
            return
        (self.directory / GATEWAY_STATE / CONSOLE_JOIN_KEY).unlink(missing_ok=True)

    def delete_tagged_nodes(self, tag, name):
        """Remove earlier devices with this tag and name, so a device that lost
        its identity does not come back as name-1."""
        nodes = json.loads(self.control("nodes", "list", "--output", "json").stdout or b"[]") or []
        for node in nodes:
            tags = [*(node.get("tags") or []), *(node.get("forced_tags") or []), *(node.get("valid_tags") or [])]
            if tag in tags and node.get("given_name", "").startswith(name):
                self.control("nodes", "delete", "--identifier", str(node["id"]), "--force")

    def set_gateway(self, enabled):
        """Turn the gateway device on or off on a running runtime; every changed
        file is restored if anything fails."""
        directory = self.directory
        metadata = validate(directory, production=True)
        spec = metadata["spec"]
        if bool(spec.get("gateway")) == enabled:
            return {"gateway": enabled, "changed": False}
        names = ["deployment.json", "runtime.env"]
        previous = {name: (directory / name).read_bytes() for name in names}
        if enabled:
            spec["gateway"] = True
            create_gateway_dirs(directory)
        else:
            spec.pop("gateway", None)
        changed = None
        try:
            replace_private(directory / "deployment.json", json.dumps(metadata, indent=2) + "\n")
            replace_private(directory / "runtime.env", runtime_env(directory, metadata))
            validate(directory, production=True)
            if enabled:
                changed = Runtime(directory)
                changed.pin_images()
                changed.prepare_gateway()
                changed.compose("up", "--detach", timeout=120)
                changed.finish_gateway()
            else:
                self.compose("rm", "--stop", "--force", "gateway", timeout=60, check=False)
                self.delete_tagged_nodes(GATEWAY_TAG, "gateway")
                (directory / GATEWAY_STATE / CONSOLE_NODE_IDENTITY).unlink(missing_ok=True)
                changed = Runtime(directory)
                changed.pin_images()
                changed.compose("up", "--detach", "--remove-orphans", timeout=120)
        except DeploymentError:
            if enabled and changed is not None:
                changed.compose("rm", "--stop", "--force", "gateway", timeout=60, check=False)
            for name, value in previous.items():
                replace_private(directory / name, value)
            try:
                Runtime(directory).compose("up", "--detach", timeout=120)
            except DeploymentError:
                pass
            raise DeploymentError("Changing the gateway failed; the previous settings were restored. Check the runtime with status before relying on it")
        return {"gateway": enabled, "changed": True}

    def apply_gateway_dns(self):
        """Make the coordinator's split DNS what the console's Gateway page chose
        (dns.json, written by the management service). Other custom DNS
        settings are kept. Returns whether anything changed."""
        metadata = validate(self.directory, production=True)
        spec = metadata["spec"]
        if not spec.get("gateway"):
            raise DeploymentError("This runtime has no gateway")
        path = self.directory / GATEWAY_CONFIG / "dns.json"
        wanted = {}
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 << 10:
                raise DeploymentError("The gateway's DNS file is not a small regular file")
            raw = load_json(path)
            if not isinstance(raw, dict) or set(raw) - {"split"} or not isinstance(raw.get("split", {}), dict):
                raise DeploymentError("The gateway's DNS file must be {\"split\": {domain: [resolvers]}}")
            wanted = raw.get("split", {})
        current = dict(spec.get("dns") or {})
        status = self.directory / GATEWAY_CONFIG / "dns-status.json"
        if (current.get("split") or {}) == wanted:
            if not status.exists():
                replace_private(status, json.dumps({"split": wanted, "appliedAt": utc_now()}) + "\n", mode=0o600)
            return {"changed": False, "restarted": False}
        if wanted:
            current["split"] = wanted
        else:
            current.pop("split", None)
        try:
            restarted = self.update_dns(current, coordinator_only=True)
        except DeploymentError as error:
            # The console shows this next to its DNS settings.
            replace_private(status, json.dumps({"split": wanted, "error": str(error), "appliedAt": utc_now()}) + "\n", mode=0o600)
            raise
        replace_private(status, json.dumps({"split": wanted, "appliedAt": utc_now()}) + "\n", mode=0o600)
        return {"changed": True, "restarted": restarted}

    def enable_console_network(self, cert, key):
        """Serve the console inside the network as well, on a running runtime.

        cert and key are the public certificate, which must now also name the
        console host. Every changed file is restored if anything fails."""
        directory = self.directory
        metadata = validate(directory, production=True)
        spec = metadata["spec"]
        if not spec.get("identity"):
            raise DeploymentError("The console inside the network needs the identity broker profile")
        if spec.get("console_in_network"):
            raise DeploymentError("The console is already served inside the network")
        spec["console_in_network"] = True
        host = console_host(spec)
        hostname(host)
        cert_pair(Path(cert), Path(key), spec["control_host"])
        if not cert_covers(Path(cert), host):
            raise DeploymentError(f"The certificate must also name {host}")
        names = ["deployment.json", "identity.json", "management.env", "runtime.env", "ingress-control.crt", "ingress-control.key", "identity-trust.pem"]
        previous = {name: (directory / name).read_bytes() for name in names}
        state = directory / CONSOLE_NODE_STATE
        created_state = not state.exists()
        enabled = None
        try:
            if created_state:
                state.mkdir(mode=0o700)
            replace_private(directory / "ingress-control.crt", read_source(cert))
            replace_private(directory / "ingress-control.key", read_source(key, private=True))
            replace_private(directory / "identity-trust.pem", (directory / "internal-ca.crt").read_bytes() + (directory / "ingress-control.crt").read_bytes())
            replace_private(directory / "identity.json", json.dumps(identity_config(spec), indent=2) + "\n")
            env = (directory / "management.env").read_text()
            replace_private(directory / "management.env", env + f"COVEE_ADDITIONAL_ORIGINS={origin(host, 443)}\n")
            replace_private(directory / "deployment.json", json.dumps(metadata, indent=2) + "\n")
            replace_private(directory / "runtime.env", runtime_env(directory, metadata))
            validate(directory, production=True)
            self.compose("stop", "ingress", "management", "identity", timeout=60)
            enabled = Runtime(directory)
            enabled.start()
        except DeploymentError:
            if enabled is not None:
                enabled.compose("rm", "--stop", "--force", "console-node", timeout=60, check=False)
            for name, value in previous.items():
                replace_private(directory / name, value)
            if created_state:
                shutil.rmtree(state, ignore_errors=True)
            try:
                self.start()
            except DeploymentError:
                pass
            raise DeploymentError("Turning on the in-network console failed; the previous settings were restored. Check the runtime with status before relying on it")
        return {"console": origin(host, 443)}

    def rename(self, control_host, dns_base_domain, cert, key):
        """Move the network to a new public name and a new name suffix for its devices.

        cert and key are the public certificate for the new names. The sign-in
        service's address changes with the public name, so the coordinator's
        accounts move to it as well: people keep their accounts, and devices keep
        their keys and reconnect once they use the new address. Every changed file
        and the coordinator database are restored if anything fails."""
        directory = self.directory
        metadata = validate(directory, production=True)
        spec = metadata["spec"]
        if not spec.get("identity"):
            raise DeploymentError("Renaming a network needs the identity broker profile")
        if any(p.get("kind") == "local" for p in spec["identity"]["providers"]):
            raise DeploymentError("Covee accounts sign in with passkeys that belong to the current name; turn Covee accounts off before renaming")
        if (control_host, dns_base_domain) == (spec["control_host"], spec["dns_base_domain"]):
            raise DeploymentError("The network already uses these names")
        renamed = json.loads(json.dumps(spec))
        renamed.update(control_host=control_host, dns_base_domain=dns_base_domain)
        for record in renamed.get("dns", {}).get("extra_records", []):
            # Extra records live inside the device name suffix, so they move with it.
            if record["name"].endswith("." + spec["dns_base_domain"]):
                record["name"] = record["name"][:-len(spec["dns_base_domain"])] + dns_base_domain
        checked = json.loads(json.dumps(renamed))
        checked["tls"] = {"control_cert_file": "/unused/cert", "control_key_file": "/unused/key"}
        validate_spec(checked)
        cert_pair(Path(cert), Path(key), control_host)
        host = console_host(renamed)
        if host and not cert_covers(Path(cert), host):
            raise DeploymentError(f"The certificate must also name {host}")
        old_issuer, new_issuer = downstream_oidc(spec)[0]["issuer"], downstream_oidc(renamed)[0]["issuer"]
        names = ["deployment.json", "headscale.yaml", "identity.json", "management.env", "runtime.env", "ingress-control.crt", "ingress-control.key", "identity-trust.pem"]
        previous = {name: (directory / name).read_bytes() for name in names}
        database = directory / "state/headscale/db.sqlite"
        database_files = [database.with_name(database.name + suffix) for suffix in ("", "-wal", "-shm")]
        running = bool(self.compose("ps", "--quiet", "headscale").stdout.strip())
        # Accounts must not change while they move, and every service reads its names only at startup.
        self.compose("stop", timeout=120)
        saved = {path: path.read_bytes() for path in database_files if path.exists()}
        try:
            config = load_json(directory / "headscale.yaml")
            config.update(server_url=origin(control_host, renamed["public_port"]), dns=dns_config(renamed), oidc=enrollment_oidc(renamed))
            lines = [line for line in (directory / "management.env").read_text().splitlines() if not line.startswith("COVEE_ADDITIONAL_ORIGINS=")]
            lines = [f"COVEE_OIDC_ISSUER={new_issuer}" if line.startswith("COVEE_OIDC_ISSUER=") else line for line in lines]
            if host:
                lines.append(f"COVEE_ADDITIONAL_ORIGINS={origin(host, 443)}")
            current = {}
            for line in (directory / "runtime.env").read_text().splitlines():
                match = re.fullmatch(r"(COVEE_[A-Z_]+)='([^'\r\n$]*)'", line)
                if match:
                    current[match[1]] = match[2]
            metadata["spec"] = renamed
            images = {name: current.get(f"COVEE_{name.upper()}_IMAGE", ref) for name, ref in runtime_images(metadata).items()}
            replace_private(directory / "ingress-control.crt", read_source(cert))
            replace_private(directory / "ingress-control.key", read_source(key, private=True))
            replace_private(directory / "identity-trust.pem", (directory / "internal-ca.crt").read_bytes() + (directory / "ingress-control.crt").read_bytes())
            replace_private(directory / "headscale.yaml", json.dumps(config, indent=2) + "\n")
            replace_private(directory / "identity.json", json.dumps(identity_config(renamed), indent=2) + "\n")
            replace_private(directory / "management.env", "".join(line + "\n" for line in lines))
            replace_private(directory / "deployment.json", json.dumps(metadata, indent=2) + "\n")
            replace_private(directory / "runtime.env", runtime_env(directory, metadata, images))
            moved = move_accounts(database, old_issuer, new_issuer) if new_issuer != old_issuer else 0
            validate(directory, production=True)
            if running:
                Runtime(directory).start()
        except DeploymentError:
            # A partly started coordinator must not hold the database while it is put back.
            self.compose("stop", timeout=120, check=False)
            for name, value in previous.items():
                replace_private(directory / name, value)
            for path in database_files:
                if path in saved:
                    replace_private(path, saved[path], mode=0o600)
                else:
                    path.unlink(missing_ok=True)
            try:
                if running:
                    Runtime(directory).start()
            except DeploymentError:
                pass
            raise DeploymentError("Renaming failed; the previous names, certificate and accounts were restored. Check the runtime with status before relying on it")
        return {"control": origin(control_host, renamed["public_port"]), "issuer": new_issuer, "devices": dns_base_domain,
                "console": origin(host, 443) if host else None, "accounts_moved": moved, "restarted": running}

    def pin_images(self):
        metadata = load_json(self.directory / "deployment.json")
        pinned = {}
        for service, tag in runtime_images(metadata).items():
            result = run(["docker", "image", "inspect", "--format", "{{.Id}}", tag])
            image_id = result.stdout.decode().strip()
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
                raise DeploymentError("Missing immutable runtime image ID")
            pinned[service] = image_id
        replace_private(self.directory / "runtime.env", runtime_env(self.directory, metadata, pinned))
        return pinned


def build(*, include_identity=False):
    run([sys.executable, ROOT / "scripts/build_headscale.py", "build"], timeout=1800)
    for service, dockerfile in (("management", ROOT / "Dockerfile"), ("ingress", ROOT / "deploy/Dockerfile.ingress")):
        run(["docker", "build", "--file", dockerfile, "--tag", IMAGES[service], ROOT], timeout=1200)
    if include_identity:
        run(["docker", "build", "--file", ROOT / "deploy/Dockerfile.identity", "--tag", IDENTITY_IMAGE, ROOT], timeout=1200)
        # Small, and needed only where the console is served inside the network.
        run(["docker", "build", "--file", ROOT / "deploy/Dockerfile.console-node", "--tag", CONSOLE_NODE_IMAGE, ROOT], timeout=1800)
        # Small, and needed only where the network has a gateway.
        run(["docker", "build", "--file", ROOT / "deploy/Dockerfile.gateway", "--tag", GATEWAY_IMAGE, ROOT], timeout=1800)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "validate", "build", "up", "down", "status", "rotate-api-key", "update-identity-grants", "update-identity-providers", "update-dns", "create-device-key", "renew-certificates", "enable-console-network", "rename", "local-accounts", "check", "backup", "restore",
                                            "enable-gateway", "disable-gateway", "apply-gateway-dns"])
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIR)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path, help="New encrypted backup file")
    parser.add_argument("--recipient", help="Public age recipient for backup")
    parser.add_argument("--archive", type=Path, help="Encrypted backup to restore into a new --directory")
    parser.add_argument("--identity", type=Path, help="External age identity file; never stored in the runtime")
    parser.add_argument("--lab", action="store_true", help="Prepare disposable configuration only; never used by production up")
    parser.add_argument("--with-identity", action="store_true", help="Also build the optional social identity broker image")
    parser.add_argument("--cert", help="renew-certificates, enable-console-network, rename: new public certificate chain for the control host")
    parser.add_argument("--key", help="renew-certificates, enable-console-network, rename: private key of that certificate")
    parser.add_argument("--control-host", help="rename: the new public hostname")
    parser.add_argument("--dns-base-domain", help="rename: the new name suffix of devices in the network")
    parser.add_argument("--tags", help="create-device-key: comma-separated tags such as tag:server")
    parser.add_argument("--action", help="local-accounts: invite, reset, update, remove or list")
    parser.add_argument("--email", help="local-accounts: the account's email address")
    parser.add_argument("--name", help="local-accounts invite: the person's name")
    parser.add_argument("--role", help="local-accounts: admin, reader or none")
    parser.add_argument("--enroll", choices=["true", "false"], help="local-accounts: whether the account may add devices")
    parser.add_argument("--expires", default="72h", help="local-accounts invite/reset: invite lifetime such as 72h")
    parser.add_argument("--expiration", default="24h", help="create-device-key: lifetime such as 30m, 24h or 7d")
    parser.add_argument("--reusable", action="store_true", help="create-device-key: allow several devices to use the key")
    parser.add_argument("--ephemeral", action="store_true", help="create-device-key: remove devices when they go offline")
    args = parser.parse_args()
    directory = args.directory.absolute()
    operation_lock = None
    try:
        if args.command == "prepare":
            if args.lab:
                spec = {"control_host": "ingress", "admin_host": "admin", "dns_base_domain": "mesh.lab.invalid",
                        "public_bind": "127.0.0.1", "public_port": 8443}
            elif args.config:
                spec = load_json(args.config)
            else:
                raise DeploymentError("Production preparation requires --config; use --lab only for disposable tests")
            prepare(directory, spec, lab=args.lab)
            print("Prepared private runtime files; no services started or host settings changed.")
        elif args.command == "build":
            build(include_identity=args.with_identity)
            print("Built the portable runtime images" + (" including the identity broker." if args.with_identity else "."))
        elif args.command == "check":
            import deploy_check
            deploy_check.check()
        elif args.command == "restore":
            import deploy_backup
            if not args.archive or not args.identity:
                raise DeploymentError("Restore requires --archive and --identity, and a new --directory")
            deploy_backup.restore(args.archive, directory, args.identity)
            print("Restored private state into a new directory; no services started or host settings changed.")
        elif args.command == "renew-certificates":
            # No validate() first: it rejects nearly expired certificates, which is what renewal fixes.
            runtime = Runtime(directory)
            operation_lock = runtime.acquire_lock()
            print(json.dumps(runtime.renew_certificates(args.cert, args.key)))
        elif args.command == "enable-console-network":
            if not args.cert or not args.key:
                raise DeploymentError("enable-console-network needs --cert and --key for a certificate that also names the console host")
            runtime = Runtime(directory)
            operation_lock = runtime.acquire_lock()
            print(json.dumps(runtime.enable_console_network(args.cert, args.key)))
        elif args.command in ("enable-gateway", "disable-gateway", "apply-gateway-dns"):
            runtime = Runtime(directory)
            operation_lock = runtime.acquire_lock()
            if args.command == "apply-gateway-dns":
                print(json.dumps(runtime.apply_gateway_dns()))
            else:
                print(json.dumps(runtime.set_gateway(args.command == "enable-gateway")))
        elif args.command == "rename":
            if not args.control_host or not args.dns_base_domain or not args.cert or not args.key:
                raise DeploymentError("rename needs --control-host, --dns-base-domain, and --cert and --key for a certificate naming the new hosts")
            runtime = Runtime(directory)
            operation_lock = runtime.acquire_lock()
            print(json.dumps(runtime.rename(args.control_host, args.dns_base_domain, args.cert, args.key)))
        elif args.command == "validate":
            metadata = validate(directory, production=not args.lab)
            Runtime(directory).compose("config", "--quiet")
            print("Configuration validation passed; live security/identity acceptance is separate.")
        else:
            metadata = validate(directory, production=args.command in ("up", "rotate-api-key", "update-identity-grants", "update-identity-providers", "update-dns", "create-device-key", "local-accounts"))
            runtime = Runtime(directory)
            operation_lock = runtime.acquire_lock()
            if args.command == "up":
                runtime.start()
                print("Started the selected runtime. Complete external exposure, identity and recovery acceptance before use.")
            elif args.command == "down":
                runtime.compose("down", timeout=120)
                print("Stopped only the selected runtime; persistent state retained.")
            elif args.command == "rotate-api-key":
                runtime.rotate_api_key()
                print("Rotated coordinator API credential and recreated management; arrange daily invocation.")
            elif args.command == "update-identity-grants":
                if not args.config:
                    raise DeploymentError("Grant updates require --config pointing to the complete intended grants JSON array")
                runtime.update_identity_grants(load_json(args.config))
                print("Updated explicit social grants and restarted the selected broker. Existing sessions and enrolled nodes require separate revocation.")
            elif args.command == "update-identity-providers":
                if not args.config:
                    raise DeploymentError("Provider updates require --config pointing to the complete intended providers JSON array")
                runtime.update_identity_providers(load_json(args.config))
                print("Updated the sign-in providers and restarted only the broker; devices and the console stayed up.")
            elif args.command == "local-accounts":
                # An invite token goes to standard output once, for the operator who asked for it.
                print(json.dumps(runtime.local_accounts(args.action, email=args.email, name=args.name, role=args.role,
                                                         enroll=None if args.enroll is None else args.enroll == "true", expires=args.expires)))
            elif args.command == "create-device-key":
                created = runtime.create_device_key((args.tags or "").split(","), expiration=args.expiration,
                                                    reusable=args.reusable, ephemeral=args.ephemeral)
                # The key goes to standard output once, for the operator who asked for it.
                print(json.dumps(created))
            elif args.command == "update-dns":
                if not args.config:
                    raise DeploymentError("DNS updates require --config pointing to the complete intended DNS settings object ({} clears them)")
                if runtime.update_dns(load_json(args.config)):
                    print("Updated DNS settings and restarted the coordinator; clients receive them when they reconnect.")
                else:
                    print("Updated DNS settings; they apply the next time the runtime starts.")
            elif args.command == "backup":
                import deploy_backup
                if not args.output or not args.recipient:
                    raise DeploymentError("Backup requires --output and a public --recipient")
                deploy_backup.backup(runtime, args.output, args.recipient)
                print("Created encrypted consistent backup; selected services returned to their prior running state.")
            else:
                print(runtime.compose("ps").stdout.decode().rstrip())
    except (DeploymentError, OSError, ValueError, KeyError) as error:
        if isinstance(error, DeploymentError):
            print("ERROR: " + str(error), file=sys.stderr)
        else:
            print("ERROR: deployment operation failed; details suppressed to protect credentials", file=sys.stderr)
        return 1
    finally:
        if operation_lock:
            operation_lock.close()
    return 0


if __name__ == "__main__":
    # Helpers must share this module's errors/classes with the CLI entrypoint.
    sys.modules["deploy"] = sys.modules[__name__]
    sys.exit(main())
