#!/usr/bin/env python3
"""Download and verify the offline parts for the LiteLLM HA gateway. Runs on Windows, Linux or macOS.

Needs only Python 3.9+ (3.11+ for the native parts; standard library only) and HTTPS access to ghcr.io,
raw/api.github.com, GitHub's blob CDN, PyPI and binaries.prisma.sh - no Docker, Podman, skopeo or cosign.

The bundle is made of independent parts. Build all of them, or only the ones you need, in one run or
in separate runs (downloads are cached and reused):

    image      signed LiteLLM container image (OCI archive)             -> container mode
    python     third-party wheels pinned by LiteLLM's uv.lock            -> native mode
    litellm    LiteLLM's own wheels + enterprise hooks                   -> native mode
    prisma     Prisma client + CLI from the image, RHEL engines          -> native mode
    installer  install.py and the guides                                  -> always useful

    py -3.12 build_bundle.py --version v1.106.2                         # all parts, one bundle tar
    py -3.12 build_bundle.py --version v1.106.2 --parts container       # image + installer
    py -3.12 build_bundle.py --version v1.106.3 --parts litellm,prisma --pack parts   # one tar per part
    py -3.12 build_bundle.py --parts installer                          # just the installer
    py -3.12 build_bundle.py                                            # asks (double-click friendly)

Every part is checked against the same verified release before it is written:
  * refuses the compromised 1.107.0 release and its known digests, and moving tags
  * cosign signature: ECDSA P-256 over the signed payload, against LiteLLM's pinned public key,
    and the payload must name this exact image digest
  * SLSA build provenance must name https://github.com/BerriAI/litellm AND the commit of the
    release tag (the 21 Oct 2026 malicious build came from the lookalike Berri-AI/litellm)
  * every downloaded blob/wheel/engine must match its sha256 digest
  * image layers and wheels are scanned for the 21 Oct payload files (cook.pth / cook.py / sitecustomize.py)
  * native parts: uv.lock resolved for the image's Python must reproduce the image's packages; LiteLLM's
    PyPI wheels must match the image file by file; Prisma client/CLI are copied from the image
The native parts download the image layers once (into the cache) for these cross-checks.

Each part is a folder with PART.json (what it is, what it needs) and SHA256SUMS. Parts that belong
together are matched by content, not by name: a litellm part names the dependency set (deps_id) and the
Prisma client (client_id) it needs, so a python part from an older build can be reused when the
dependencies did not change. The installer finds parts in folders, part tars and bundle tars.
"""
import argparse
import base64
import csv
import datetime
import email.parser
import gzip
import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REGISTRY = "ghcr.io"
REPOSITORY = "berriai/litellm"
EXPECTED_SOURCE = "https://github.com/BerriAI/litellm"

# LiteLLM's cosign public key, pinned. Source: cosign.pub at commit 0112e53 (the commit that
# introduced it); identical to the key printed in LiteLLM's Docker Image Security Guide.
COSIGN_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKi4ivqGpE231OGH50PKbqy1Y1Kkb
POJC8+i2Wko82gBOUCe3M0Vw86H/4rhUhfoYEti4gdJ9wZbYmK0I2EE96g==
-----END PUBLIC KEY-----
"""
COSIGN_PUB_URL = ("https://raw.githubusercontent.com/BerriAI/litellm/"
                  "0112e53046018d726492c814b3644b7d376029d0/cosign.pub")

# 21 Oct 2026 supply-chain compromise (LiteLLM incident report, Wiz, StepSecurity).
BAD_VERSIONS = {"1.107.0"}
BAD_DIGESTS = {
    "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e",  # index litellm:v1.107.0
    "sha256:bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5",  # linux/amd64
    "sha256:56b74573eed6e4aafe4b50603dbe7853e0345f188c8e44a09f1098caf1f4bcdf",  # linux/arm64
}
PAYLOAD_RE = re.compile(r"(^|/)site-packages/(cook\.pth|cook\.py|sitecustomize\.py)$")
PTH_RE = re.compile(r"(^|/)site-packages/[^/]+\.pth$")
ARCHES = ("amd64", "arm64")
ARCH_TO_MACHINE = {"amd64": "x86_64", "arm64": "aarch64"}
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST_ACCEPT = ", ".join([
    OCI_INDEX,
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
COSIGN_LAYER = "application/vnd.dev.cosign.simplesigning.v1+json"


class BuildError(Exception):
    pass


def info(text):
    print(f"==> {text}", flush=True)


def detail(text):
    print(f"    {text}", flush=True)


def warn(text):
    print(f"WARNING: {text}", file=sys.stderr, flush=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ============================================================================ network: proxy + errors
NETWORK = {"proxy": None, "source": "direct connection"}
CHECK_TARGETS = [
    ("ghcr.io", "https://ghcr.io/token?service=ghcr.io&scope=repository:berriai/litellm:pull", "image registry"),
    ("pkg-containers.githubusercontent.com", "https://pkg-containers.githubusercontent.com/", "image layers (CDN)"),
    ("raw.githubusercontent.com", COSIGN_PUB_URL, "cosign key, uv.lock"),
    ("api.github.com", "https://api.github.com/repos/BerriAI/litellm", "release tag -> commit"),
    ("pypi.org", "https://pypi.org/simple/litellm-proxy-extras/", "LiteLLM wheel metadata"),
    ("files.pythonhosted.org", "https://files.pythonhosted.org/", "wheels"),
    ("binaries.prisma.sh", "https://binaries.prisma.sh/", "Prisma engines"),
]


class NetworkError(BuildError):
    pass


def proxy_handler():
    proxy = NETWORK["proxy"]
    return urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})


def windows_internet_settings():
    """Proxy values from the Windows 'Internet Options' of the current user (what browsers use)."""
    if os.name != "nt":
        return {}
    import winreg
    values = {}
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    except OSError:
        return values
    for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"):
        try:
            values[name] = winreg.QueryValueEx(key, name)[0]
        except OSError:
            pass
    return values


def windows_system_proxy(url="https://ghcr.io/"):
    """Ask Windows which proxy it would use for url - this evaluates PAC scripts and WPAD, which
    Python itself does not. Returns 'http://host:port' or None (direct / unknown)."""
    if os.name != "nt":
        return None
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        return None
    script = (f"$u=[Uri]'{url}'; $p=[System.Net.WebRequest]::GetSystemWebProxy(); "
              "$r=$p.GetProxy($u); if ($r.AbsoluteUri -ne $u.AbsoluteUri) { $r.AbsoluteUri }")
    try:
        result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    answer = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
    return answer.rstrip("/") if re.match(r"^https?://[^/\s]+", answer) else None


def setup_proxy(choice):
    """--proxy URL | none | auto (default: HTTPS_PROXY, else the system proxy, else Windows PAC/WPAD)."""
    choice = (choice or "auto").strip()
    proxy, source = None, "direct connection"
    if choice.lower() == "none":
        source = "direct connection (--proxy none)"
    elif choice.lower() != "auto":
        proxy, source = choice, "--proxy"
    else:
        system = urllib.request.getproxies()       # environment, or the manual Windows/macOS proxy
        proxy = system.get("https") or system.get("http")
        if proxy:
            source = "HTTPS_PROXY / system proxy settings"
        else:
            proxy = windows_system_proxy()
            if proxy:
                source = "Windows automatic proxy configuration (PAC/WPAD)"
    if proxy and "://" not in proxy:
        proxy = "http://" + proxy
    NETWORK.update(proxy=proxy, source=source)
    urllib.request.install_opener(urllib.request.build_opener(proxy_handler()))
    shown = re.sub(r"//[^/@]*@", "//***@", proxy) if proxy else None
    info(f"Network: {'proxy ' + shown if proxy else 'no proxy'} ({source})")


CUT_OFF = ("unexpected_eof", "eof occurred", "10054", "reset by peer", "connection aborted", "10053",
           "remote end closed", "connection reset")


def _shown(proxy):
    return re.sub(r"//[^/@]*@", "//***@", proxy) if proxy else "no proxy"


def _explain(url, exc, proxy=None):
    host = urllib.parse.urlparse(url).hostname or url
    reason = str(getattr(exc, "reason", exc))
    proxy = NETWORK["proxy"] if proxy is None else proxy
    via = f"through proxy {_shown(proxy)}" if proxy else "directly (no proxy)"
    text = f"cannot reach {host} {via}: {reason}"
    low = reason.lower()
    if "407" in reason:
        text += ("\n  The proxy wants a login. Use --proxy http://USER:PASSWORD@host:port (basic auth); for "
                 "Windows-integrated (NTLM/Kerberos) proxies run a local helper such as px or cntlm and use "
                 "--proxy http://127.0.0.1:3128")
    elif any(k in low for k in CUT_OFF):
        text += (f"\n  The connection was cut during the TLS handshake. A firewall, proxy or antivirus web filter "
                 f"usually does this when it does not allow {host}"
                 + (" - ask IT to allow it on the proxy, or compare with --proxy none."
                    if proxy else
                    " for direct connections. This network probably requires its proxy: find it with "
                    "build_bundle.py --check-network and use --proxy http://host:port."))
    elif not proxy and any(k in low for k in ("10060", "timed out", "10061", "refused", "unreachable", "11001",
                                                "getaddrinfo", "name or service")):
        text += ("\n  This network probably only allows the internet through a proxy. Find it with: "
                 "build_bundle.py --check-network, then run again with --proxy http://host:port")
    elif proxy:
        text += "\n  Check the proxy address/port, or test with: build_bundle.py --check-network"
    if "certificate" in low:
        text += ("\n  TLS inspection? Point SSL_CERT_FILE at a PEM file with your company's root CA "
                 "(plus the usual public roots)")
    return text


def open_url(request, timeout=60, opener=None, proxy=None, attempts=3):
    """urlopen with the chosen proxy and an explained error naming the host (HTTP errors pass through).

    Connections cut off mid-handshake are retried a few times: some proxies/firewalls drop them now and then."""
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    if opener is None:
        opener = urllib.request.build_opener(proxy_handler() if proxy is None else urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy} if proxy else {}))
    for attempt in range(1, attempts + 1):
        try:
            return opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 407:
                raise NetworkError(_explain(url, exc, proxy))
            raise
        except (urllib.error.URLError, OSError) as exc:
            cut_off = any(k in str(getattr(exc, "reason", exc)).lower() for k in CUT_OFF)
            if cut_off and attempt < attempts:
                time.sleep(2 * attempt)
                continue
            raise NetworkError(_explain(url, exc, proxy))


def _probe(url, proxy, timeout=20):
    """One HEAD request; returns (ok, text). Any HTTP status counts as reachable."""
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "litellm-ha-bundler"})
    started = time.time()
    try:
        with open_url(request, timeout=timeout, proxy=proxy or "", attempts=2) as resp:
            return True, f"HTTP {resp.status}, {time.time() - started:.1f} s"
    except urllib.error.HTTPError as exc:
        return True, f"HTTP {exc.code}, {time.time() - started:.1f} s"
    except NetworkError as exc:
        return False, str(exc)


def check_network():
    """Report how this PC reaches every host the build needs; for failing hosts, try the other route
    (direct vs proxy) and say which one works. Returns 0 when all are reachable."""
    info("This PC")
    detail(f"Python {platform.python_version()} on {platform.platform()}, {ssl.OPENSSL_VERSION}")
    info("Proxy settings seen on this PC")
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY"):
        if os.environ.get(key):
            detail(f"environment {key} = {_shown(os.environ[key])}")
    for key, value in windows_internet_settings().items():
        detail(f"Windows Internet Options {key} = {value}")
    windows_proxy = windows_system_proxy() if os.name == "nt" else None
    if os.name == "nt":
        detail(f"Windows would use for https://ghcr.io/: {_shown(windows_proxy) if windows_proxy else 'a direct connection'}")
    current = NETWORK["proxy"] or ""
    detail(f"this run uses: {_shown(current) if current else 'no proxy'} ({NETWORK['source']})")
    alternatives = [p for p in dict.fromkeys([""] + [windows_proxy or ""]) if p != current]

    info("Reaching the download hosts")
    failed, advice = [], set()
    for host, url, purpose in CHECK_TARGETS:
        try:
            address = socket.getaddrinfo(host, 443)[0][4][0]
        except OSError:
            address = "no local DNS" + (" (fine with a proxy)" if current else "")
        ok, text = _probe(url, current)
        if ok:
            print(f"  [ ok ] {host:<38} {purpose}  ({text}, {address})", flush=True)
            continue
        failed.append(host)
        print(f"  [FAIL] {host:<38} {purpose}  ({address})\n         {text}", flush=True)
        for other in alternatives:
            alt_ok, alt_text = _probe(url, other)
            route = f"via {_shown(other)}" if other else "directly"
            print(f"         {'works' if alt_ok else 'also fails'} {route}" + (f" ({alt_text})" if alt_ok else ""),
                  flush=True)
            if alt_ok:
                advice.add(f"--proxy {other}" if other else "--proxy none")
    if failed:
        print(f"\n{len(failed)} host(s) unreachable: {', '.join(failed)}.")
        if advice:
            print("Run the build with: " + " or ".join(sorted(advice)))
        else:
            print("No route found from this PC. Ask the network team to allow these hosts (through the proxy), "
                  "or run with --proxy http://host:port (the proxy your browser uses).")
        return 1
    print("\nAll hosts reachable - the build should work with these settings.")
    return 0


# ============================================================================ ECDSA P-256 (verify only)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
OID_PRIME256V1 = bytes.fromhex("06082a8648ce3d030107")


def _on_curve(point):
    x, y = point
    return 0 <= x < P256_P and 0 <= y < P256_P and (y * y - (x * x * x + P256_A * x + P256_B)) % P256_P == 0


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        slope = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    return x3, (slope * (x1 - x3) - y1) % P256_P


def _ec_mul(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = _ec_add(result, point)
        point = _ec_add(point, point)
        scalar >>= 1
    return result


def _der_read(data, pos):
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, data[pos:pos + length], pos + length


def load_p256_public_key(pem):
    der = base64.b64decode("".join(line for line in pem.splitlines() if line and not line.startswith("-----")))
    if OID_EC_PUBLIC_KEY not in der or OID_PRIME256V1 not in der:
        raise BuildError("cosign key is not an ECDSA P-256 public key")
    point = der[-65:]
    if point[0] != 0x04:
        raise BuildError("cosign key is not an uncompressed P-256 point")
    public = (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big"))
    if not _on_curve(public):
        raise BuildError("cosign key point is not on the P-256 curve")
    return public


def ecdsa_p256_verify(public, message, der_signature):
    """Standard ECDSA verification (SHA-256) of a DER-encoded signature."""
    try:
        tag, sequence, _ = _der_read(der_signature, 0)
        tag_r, r_bytes, pos = _der_read(sequence, 0)
        tag_s, s_bytes, _ = _der_read(sequence, pos)
    except IndexError:
        return False
    if tag != 0x30 or tag_r != 0x02 or tag_s != 0x02:
        return False
    r, s = int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, P256_N)
    point = _ec_add(_ec_mul(e * w % P256_N, P256_G), _ec_mul(r * w % P256_N, public))
    return point is not None and point[0] % P256_N == r


# ============================================================================ registry API
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Registry:
    """Minimal read-only OCI registry client (anonymous pull token, system proxy settings honoured)."""

    def __init__(self, registry=REGISTRY, repository=REPOSITORY):
        self.base = f"https://{registry}/v2/{repository}"
        token_url = f"https://{registry}/token?service={registry}&scope=repository:{repository}:pull"
        with open_url(token_url, timeout=30) as resp:
            self.token = json.load(resp)["token"]
        self._opener = urllib.request.build_opener(proxy_handler(), _NoRedirect)

    def _open(self, url, accept=None, timeout=120):
        headers = {"Authorization": f"Bearer {self.token}"}
        if accept:
            headers["Accept"] = accept
        try:
            return open_url(urllib.request.Request(url, headers=headers), timeout=timeout, opener=self._opener)
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                # Blob storage uses pre-signed URLs: follow WITHOUT the registry token.
                return open_url(urllib.parse.urljoin(url, exc.headers["Location"]), timeout=timeout)
            raise

    def manifest(self, reference):
        with self._open(f"{self.base}/manifests/{reference}", MANIFEST_ACCEPT) as resp:
            body, served = resp.read(), resp.headers.get("Docker-Content-Digest")
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        if served and served != digest:
            raise BuildError(f"registry digest {served} does not match the content ({digest})")
        return body, digest

    def blob(self, digest):
        with self._open(f"{self.base}/blobs/{digest}") as resp:
            body = resp.read()
        if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
            raise BuildError(f"blob {digest} failed its checksum")
        return body

    def download_blob(self, digest, size, target, label, attempts=4):
        """Stream a blob to disk, verifying size and digest; resumes nothing but retries cleanly."""
        if target.exists() and target.stat().st_size == size and "sha256:" + sha256_file(target) == digest:
            detail(f"{label}: already downloaded")
            return
        for attempt in range(1, attempts + 1):
            partial = target.with_name(target.name + ".part")
            hasher, count, started = hashlib.sha256(), 0, time.time()
            try:
                with self._open(f"{self.base}/blobs/{digest}", timeout=300) as resp, open(partial, "wb") as out:
                    for chunk in iter(lambda: resp.read(1 << 20), b""):
                        out.write(chunk)
                        hasher.update(chunk)
                        count += len(chunk)
                if count != size or "sha256:" + hasher.hexdigest() != digest:
                    raise BuildError(f"{label}: size/digest mismatch")
                os.replace(partial, target)
                rate = count / 2**20 / max(time.time() - started, 0.001)
                detail(f"{label}: {count / 2**20:7.1f} MiB  ok  ({rate:.1f} MiB/s)")
                return
            except (OSError, BuildError) as exc:
                if partial.exists():
                    partial.unlink()
                if attempt == attempts:
                    raise BuildError(f"{label}: download failed after {attempts} attempts: {exc}")
                warn(f"{label}: {exc} - retrying ({attempt}/{attempts})")
                time.sleep(3 * attempt)


def resolve_index(registry, version):
    body, digest = registry.manifest(version)
    document = json.loads(body)
    if "manifests" not in document:
        raise BuildError(f"{version} is a single-platform manifest; expected a multi-platform index")
    return body, digest, document


def platform_digest(index, arch):
    for entry in index["manifests"]:
        plat = entry.get("platform", {})
        if plat.get("os") == "linux" and plat.get("architecture") == arch:
            return entry["digest"]
    raise BuildError(f"the image has no linux/{arch} variant")


# ============================================================================ signature & provenance
def verify_cosign(registry, index_digest):
    """Verify LiteLLM's cosign signature(s) on the index digest. Returns the number of valid signatures."""
    public = load_p256_public_key(COSIGN_PUBLIC_KEY)
    try:
        with open_url(COSIGN_PUB_URL, timeout=30) as resp:
            online = resp.read().decode()
    except (OSError, ValueError, NetworkError):
        online = None
        warn("could not re-fetch the published cosign key; using the pinned copy")
    if online and load_p256_public_key(online) != public:
        raise BuildError("the cosign key published at the pinned commit differs from the key in this script")
    try:
        body, _ = registry.manifest("sha256-" + index_digest.split(":", 1)[1] + ".sig")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise BuildError("no cosign signature is published for this image digest")
        raise
    valid = 0
    for layer in json.loads(body).get("layers", []):
        signature = layer.get("annotations", {}).get("dev.cosignproject.cosign/signature")
        if layer.get("mediaType") != COSIGN_LAYER or not signature:
            continue
        payload = registry.blob(layer["digest"])
        if not ecdsa_p256_verify(public, payload, base64.b64decode(signature)):
            continue
        claims = json.loads(payload).get("critical", {})
        if (claims.get("image", {}).get("docker-manifest-digest") == index_digest
                and claims.get("identity", {}).get("docker-reference") == f"{REGISTRY}/{REPOSITORY}"):
            valid += 1
    if not valid:
        raise BuildError("no valid signature from LiteLLM's cosign key covers this exact image digest")
    return valid


def _vcs_fields(node, parent=""):
    """Collect BuildKit VCS source/revision values from a SLSA v0.2 or v1 provenance document."""
    sources, revisions = [], []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and (key == "vcs:source" or (parent == "vcs" and key == "source")):
                sources.append(value)
            elif isinstance(value, str) and (key == "vcs:revision" or (parent == "vcs" and key == "revision")):
                revisions.append(value)
            else:
                more_sources, more_revisions = _vcs_fields(value, key)
                sources += more_sources
                revisions += more_revisions
    elif isinstance(node, list):
        for value in node:
            more_sources, more_revisions = _vcs_fields(value, parent)
            sources += more_sources
            revisions += more_revisions
    return sources, revisions


def check_provenance(registry, index, image_digest):
    """Verify the image's SLSA provenance names the official repo. Returns (json_text, revision)."""
    attestation = None
    for entry in index["manifests"]:
        annotations = entry.get("annotations", {})
        if (annotations.get("vnd.docker.reference.type") == "attestation-manifest"
                and annotations.get("vnd.docker.reference.digest") == image_digest):
            attestation = entry["digest"]
    if not attestation:
        raise BuildError("no build-provenance attestation found for this image")
    body, _ = registry.manifest(attestation)
    provenance = None
    for layer in json.loads(body).get("layers", []):
        if "slsa.dev/provenance" in layer.get("annotations", {}).get("in-toto.io/predicate-type", ""):
            provenance = registry.blob(layer["digest"]).decode("utf-8", errors="replace")
    if provenance is None:
        raise BuildError("attestation has no SLSA provenance layer")
    sources, revisions = _vcs_fields(json.loads(provenance).get("predicate", {}))
    if not sources or not revisions:
        raise BuildError("provenance does not record the VCS source/revision")
    wrong = sorted({s for s in sources if s.rstrip("/").removesuffix(".git") != EXPECTED_SOURCE})
    if wrong:
        raise BuildError(f"image was built from {', '.join(wrong)}, not {EXPECTED_SOURCE} - DO NOT USE")
    if len(set(revisions)) != 1:
        raise BuildError(f"provenance records several revisions: {sorted(set(revisions))}")
    return provenance, revisions[0]


def tag_commit(version):
    """Commit SHA the official GitHub tag points to (dereferencing annotated tags)."""
    api = "https://api.github.com/repos/BerriAI/litellm/git"
    headers = {"Accept": "application/vnd.github+json"}

    def fetch(url):
        with open_url(urllib.request.Request(url, headers=headers), timeout=30) as resp:
            return json.load(resp)["object"]

    obj = fetch(f"{api}/ref/tags/{version}")
    for _ in range(5):
        if obj["type"] == "commit":
            return obj["sha"]
        obj = fetch(f"{api}/tags/{obj['sha']}")
    raise BuildError(f"could not resolve tag {version} to a commit")


# ============================================================================ image download & scan
_SITE_RE = re.compile(r"^(app/\.venv/lib/python(3\.\d+)/site-packages/)")
_ENGINE_HASH_RE = re.compile(r"expected_engine_version: str = Field\([^)]*default='([0-9a-f]{40})'", re.S)


def scan_layer(path, media_type, facts):
    """Return (payload_hits, pth_files) for one layer tarball and record image facts in `facts`."""
    if media_type.endswith("+zstd"):
        return None, []
    mode = "r|gz" if media_type.endswith("+gzip") or media_type.endswith(".tar.gzip") else "r|*"
    hits, pth = [], []
    with open(path, "rb") as fh, tarfile.open(fileobj=fh, mode=mode) as layer:
        for member in layer:
            name = member.name.lstrip("./")
            if PAYLOAD_RE.search(name):
                hits.append(name)
            elif PTH_RE.search(name):
                pth.append(name)
            site = _SITE_RE.match(name)
            if not site or not member.isfile():
                if name == "opt/prisma/binaries/node_modules/prisma/package.json" and member.isfile():
                    facts["prisma_cli_version"] = json.loads(layer.extractfile(member).read()).get("version")
                continue
            facts["site_packages"], facts["image_python"] = site.group(1), site.group(2)
            rel = name[len(site.group(1)):]
            if re.match(r"[^/]+\.dist-info/METADATA$", rel):
                meta = email.parser.Parser().parsestr(
                    layer.extractfile(member).read().decode("utf-8", "replace"), headersonly=True)
                facts.setdefault("dists", {})[rel.split("/")[0]] = (norm(meta["Name"]), meta["Version"])
            elif re.match(r"(litellm|litellm_enterprise|litellm_proxy_extras)-[^/]+\.dist-info/RECORD$", rel):
                key = norm(rel.split("-")[0])
                facts.setdefault("image_records", {})[key] = layer.extractfile(member).read().decode()
            elif rel == "prisma/_config.py":
                match = _ENGINE_HASH_RE.search(layer.extractfile(member).read().decode())
                if match:
                    facts["engine_hash"] = match.group(1)
    return hits, pth


def _safe_member(entry):
    """Root-owned, not world-writable: Windows reports 0666/0777, which root's tar would keep."""
    entry.uid = entry.gid = 0
    entry.uname = entry.gname = "root"
    if entry.isdir():
        entry.mode = 0o755
    else:
        entry.mode = 0o755 if entry.name.endswith(("install.py", "build_bundle.py")) else 0o644
    return entry


def _add_bytes(tar, name, data):
    entry = tarfile.TarInfo(name)
    entry.size, entry.mtime = len(data), int(time.time())
    tar.addfile(_safe_member(entry), io.BytesIO(data))


def _add_dir(tar, name):
    entry = tarfile.TarInfo(name)
    entry.type, entry.mtime = tarfile.DIRTYPE, int(time.time())
    tar.addfile(_safe_member(entry))


def write_oci_archive(archive, manifest, manifest_body, image_digest, local_tag, arch, cache, digests):
    info(f"Writing OCI archive {archive.name}")
    index_doc = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [{
        "mediaType": manifest.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
        "digest": image_digest, "size": len(manifest_body),
        "annotations": {"org.opencontainers.image.ref.name": local_tag},
        "platform": {"architecture": arch, "os": "linux"},
    }]}
    partial = archive.with_name(archive.name + ".part")
    with tarfile.open(partial, "w", format=tarfile.PAX_FORMAT) as tar:
        _add_bytes(tar, "oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
        _add_bytes(tar, "index.json", json.dumps(index_doc).encode())
        _add_dir(tar, "blobs")
        _add_dir(tar, "blobs/sha256")
        _add_bytes(tar, "blobs/sha256/" + image_digest.split(":", 1)[1], manifest_body)
        for digest in sorted(digests):
            hexdigest = digest.split(":", 1)[1]
            tar.add(str(cache / hexdigest), arcname=f"blobs/sha256/{hexdigest}", filter=_safe_member)
    os.replace(partial, archive)


# ============================================================================ native mode: uv.lock resolution
NATIVE_EXTRAS = ["proxy", "proxy-runtime", "extra-proxy", "semantic-router", "saml", "bedrock-realtime"]
IMAGE_GROUPS = ["admin-mcp"]                      # the image also installs this group (git archive, not a wheel)
WORKSPACE = {"litellm", "litellm-enterprise", "litellm-proxy-extras"}
NOT_NATIVE = {"litellm-admin-mcp"}                # only published as a GitHub source archive
VERSION_VARS = {"python_version", "python_full_version", "implementation_version"}
_MARKER_TOKEN = re.compile(r"\s*(\(|\)|'[^']*'|\"[^\"]*\"|===|==|!=|<=|>=|~=|<|>|not\s+in\b|in\b|and\b|or\b"
                           r"|[A-Za-z_][A-Za-z0-9_.]*)")
ENGINE_PLATFORM = {"amd64": "rhel-openssl-3.0.x", "arm64": "linux-arm64-openssl-3.0.x"}
GLIBC = (2, 34)                                   # RHEL 9


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def marker_env(python, arch):
    return {"python_version": python, "python_full_version": python + ".0", "implementation_version": python + ".0",
            "implementation_name": "cpython", "platform_python_implementation": "CPython", "sys_platform": "linux",
            "platform_system": "Linux", "os_name": "posix", "platform_machine": ARCH_TO_MACHINE[arch]}


def _version_tuple(text):
    parts = []
    for piece in text.split("."):
        match = re.match(r"\d+", piece)
        if not match:
            break
        parts.append(int(match.group()))
    return tuple(parts)


def _compare_versions(left, op, right):
    if op in ("==", "!=") and right.endswith(".*"):
        prefix = _version_tuple(right[:-2])
        same = _version_tuple(left)[:len(prefix)] == prefix
        return same if op == "==" else not same
    if op == "===":
        return left == right
    a, b = _version_tuple(left), _version_tuple(right)
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    if op == "~=":
        keep = max(len(_version_tuple(right)) - 1, 1)
        return a >= b and a[:keep] == b[:keep]
    return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


class _Marker:
    """Minimal PEP 508 environment-marker evaluator (enough for uv.lock)."""

    def __init__(self, text, env):
        self.tokens, pos, text = [], 0, text.strip()
        while pos < len(text):
            match = _MARKER_TOKEN.match(text, pos)
            if not match:
                raise BuildError(f"cannot parse marker {text!r}")
            self.tokens.append(re.sub(r"\s+", " ", match.group(1)))
            pos = match.end()
        self.pos, self.env = 0, env

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self):
        token = self._peek()
        if token is None:
            raise BuildError("truncated marker")
        self.pos += 1
        return token

    def evaluate(self):
        value = self._or()
        if self.pos != len(self.tokens):
            raise BuildError(f"unexpected marker token {self._peek()!r}")
        return value

    def _or(self):
        value = self._and()
        while self._peek() == "or":
            self.pos += 1
            other = self._and()
            value = value or other
        return value

    def _and(self):
        value = self._atom()
        while self._peek() == "and":
            self.pos += 1
            other = self._atom()
            value = value and other
        return value

    def _value(self, token):
        if token[0] in "'\"":
            return token[1:-1], False
        if token in self.env:
            return self.env[token], token in VERSION_VARS
        if token == "extra":
            return "", False
        raise BuildError(f"unknown marker variable {token!r}")

    def _atom(self):
        if self._peek() == "(":
            self.pos += 1
            value = self._or()
            if self._take() != ")":
                raise BuildError("unbalanced parenthesis in marker")
            return value
        left, op, right = self._take(), self._take(), self._take()
        (lval, lver), (rval, rver) = self._value(left), self._value(right)
        if op in ("in", "not in"):
            return (lval in rval) == (op == "in")
        if lver:
            return _compare_versions(lval, op, rval)
        if rver:
            mirror = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}.get(op, op)
            return _compare_versions(rval, mirror, lval)
        if op in ("==", "!="):
            return (lval == rval) == (op == "==")
        raise BuildError(f"unsupported string comparison {op!r} in marker")


def marker_true(text, env):
    return _Marker(text, env).evaluate()


def resolve_lock(lock, root, extras, groups, env):
    """Walk uv.lock from root[extras]+groups for one target environment. Returns {norm_name: package}."""
    by_name = {}
    for package in lock["package"]:
        by_name.setdefault(norm(package["name"]), []).append(package)

    def pick(name, version):
        candidates = [p for p in by_name.get(name, []) if version is None or p["version"] == version]
        if len(candidates) > 1:
            candidates = [p for p in candidates if not p.get("resolution-markers")
                          or any(marker_true(m, env) for m in p["resolution-markers"])]
        if len(candidates) != 1:
            raise BuildError(f"uv.lock: cannot choose a version of {name} ({len(candidates)} candidates)")
        return candidates[0]

    selected = {}
    queue = [(pick(norm(root), None), {norm(e) for e in extras}, True)]
    while queue:
        package, wanted, is_root = queue.pop()
        key = norm(package["name"])
        known = selected.get(key)
        if known and known[0]["version"] != package["version"]:
            raise BuildError(f"uv.lock: conflicting versions for {key}")
        new_extras = wanted - (known[1] if known else set())
        if known and not new_extras:
            continue
        selected[key] = (package, (known[1] if known else set()) | wanted)
        deps = [] if known else list(package.get("dependencies", []))
        for extra in new_extras:
            deps += package.get("optional-dependencies", {}).get(extra, [])
        if is_root and not known:
            for group in groups:
                deps += package.get("dev-dependencies", {}).get(group, [])
        for dep in deps:
            if "marker" in dep and not marker_true(dep["marker"], env):
                continue
            queue.append((pick(norm(dep["name"]), dep.get("version")), {norm(e) for e in dep.get("extra", [])}, False))
    return {key: value[0] for key, value in selected.items()}


def wheel_score(filename, python, arch):
    """Higher is better; None if the wheel cannot run on RHEL 9 / CPython <python> / <arch>."""
    match = re.match(r"^(.+?)-([^-]+)(?:-(\d[^-]*))?-([^-]+)-([^-]+)-([^-]+)\.whl$", filename)
    if not match:
        return None
    machine, minor = ARCH_TO_MACHINE[arch], int(python.split(".")[1])
    platform_ok = False
    for tag in match.group(6).split("."):
        many = re.match(rf"manylinux_(\d+)_(\d+)_{machine}$", tag)
        if tag == "any" or (many and (int(many.group(1)), int(many.group(2))) <= GLIBC) \
                or tag in (f"manylinux2014_{machine}", f"manylinux2010_{machine}", f"manylinux1_{machine}"):
            platform_ok = True
    if not platform_ok:
        return None
    best = None
    for py in match.group(4).split("."):
        for abi in match.group(5).split("."):
            if py == "cp3" + str(minor) and abi == "cp3" + str(minor):
                score = 3
            elif re.match(r"cp3\d+$", py) and abi == "abi3" and int(py[3:]) <= minor:
                score = 2
            elif py.startswith("py3") and abi == "none":
                score = 1
            else:
                continue
            best = score if best is None else max(best, score)
    return best


def fetch_to_file(url, target, sha256, label, attempts=4):
    """Download url to target, verifying the sha256 hex digest. Skips files already present and valid."""
    if target.exists() and sha256_file(target) == sha256:
        return target.stat().st_size
    for attempt in range(1, attempts + 1):
        partial, hasher, count = target.with_name(target.name + ".part"), hashlib.sha256(), 0
        try:
            with open_url(urllib.request.Request(url, headers={"User-Agent": "litellm-ha-bundler"}),
                          timeout=300) as resp, open(partial, "wb") as out:
                for chunk in iter(lambda: resp.read(1 << 20), b""):
                    out.write(chunk)
                    hasher.update(chunk)
                    count += len(chunk)
            if hasher.hexdigest() != sha256:
                raise BuildError(f"{label}: sha256 mismatch")
            os.replace(partial, target)
            return count
        except (OSError, BuildError) as exc:
            if partial.exists():
                partial.unlink()
            if attempt == attempts:
                raise BuildError(f"{label}: download failed after {attempts} attempts: {exc}")
            warn(f"{label}: {exc} - retrying ({attempt}/{attempts})")
            time.sleep(3 * attempt)


def fetch_text(url):
    with open_url(urllib.request.Request(url, headers={"User-Agent": "litellm-ha-bundler"}),
                  timeout=60) as resp:
        return resp.read().decode()


def _record_hashes(text):
    hashes = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1]:
            hashes[row[0]] = row[1]
    return hashes


def scan_wheel(path):
    """Fail on the 21 Oct payload files at the site-packages root of a wheel; return its root .pth files.

    The payload landed in site-packages itself (wheel root or <dist>.data/purelib|platlib/); a package's
    own sitecustomize.py inside its directory (e.g. ddtrace/bootstrap/) is legitimate."""
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
    roots = [re.sub(r"^[^/]+\.data/(purelib|platlib)/", "", n) for n in names]
    roots = [n for n in roots if "/" not in n]
    bad = [n for n in roots if n in ("cook.pth", "cook.py", "sitecustomize.py")]
    if bad:
        raise BuildError(f"MALWARE payload files in {path.name}: {', '.join(bad)}")
    return [f"{path.name}: {n}" for n in roots if n.endswith(".pth")]


def _member_name(member):
    name = member.name[2:] if member.name.startswith("./") else member.name
    return name.lstrip("/")


def extract_subtrees(layers, specs):
    """Copy directory trees out of the image layers into tar files, honouring whiteouts.

    specs: list of (output_tar, source_prefix, target_prefix, exclude_regex_or_None)."""
    winners = {}
    for index, layer in enumerate(layers):
        with tarfile.open(layer, "r|gz") as tar:
            for member in tar:
                name = _member_name(member)
                base, parent = name.rsplit("/", 1)[-1], name.rsplit("/", 1)[0] if "/" in name else ""
                if base.startswith(".wh."):
                    gone = parent if base == ".wh..wh..opq" else (parent + "/" if parent else "") + base[4:]
                    for key in [k for k, owner in winners.items() if owner < index
                                and (k[1] == gone or k[1].startswith(gone + "/"))]:
                        del winners[key]
                    continue
                for spec_index, (_, prefix, _, exclude) in enumerate(specs):
                    if name.startswith(prefix) and not (exclude and re.search(exclude, name)):
                        winners[(spec_index, name)] = index
    outputs = [tarfile.open(spec[0], "w", format=tarfile.PAX_FORMAT) for spec in specs]
    counts = [0] * len(specs)
    try:
        for index, layer in enumerate(layers):
            wanted = {name: spec for (spec, name), owner in winners.items() if owner == index}
            if not wanted:
                continue
            with tarfile.open(layer, "r|gz") as tar:
                for member in tar:
                    name = _member_name(member)
                    spec_index = wanted.get(name)
                    if spec_index is None or not (member.isfile() or member.isdir() or member.issym()):
                        continue
                    _, prefix, target, _ = specs[spec_index]
                    entry = tarfile.TarInfo(target + name[len(prefix):])
                    entry.type, entry.size, entry.mtime = member.type, member.size, member.mtime
                    entry.linkname = member.linkname
                    if member.isdir():
                        entry.mode = 0o755
                    elif member.issym():
                        entry.mode = 0o777
                    else:
                        entry.mode = 0o755 if member.mode & 0o111 else 0o644
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = "root"
                    outputs[spec_index].addfile(entry, tar.extractfile(member) if member.isfile() else None)
                    counts[spec_index] += 1
    finally:
        for output in outputs:
            output.close()
    return counts


# ============================================================================ the verified release (shared by all parts)
def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def place(source, target):
    """Put a cached file into a part folder: hard link when possible (no extra disk), else copy."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def cached_fetch(cache, url, sha256, label):
    """Download into the content-addressed cache (by sha256) once; later runs reuse the verified file."""
    files = cache / "files"
    files.mkdir(parents=True, exist_ok=True)
    target = files / sha256
    size = fetch_to_file(url, target, sha256, label)
    return target, size


def tree_id(tar_path):
    """Content identity of a tar: names, types and file hashes (not timestamps)."""
    lines = []
    with tarfile.open(tar_path) as tar:
        for member in tar:
            if member.isfile():
                value = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
            else:
                value = member.linkname
            lines.append(f"{member.name}\t{member.type.decode()}\t{value}")
    return sha256_text("\n".join(sorted(lines)) + "\n")


class Release:
    """One LiteLLM release for one architecture. Every part is built from this verified source of truth.

    Cheap checks (signature, provenance) always run. Layers are downloaded only for parts that need
    them, into a persistent cache, so parts can be built in separate runs without downloading twice."""

    def __init__(self, version, arch, cache):
        self.version, self.arch, self.cache = version, arch, cache
        self.blobs = cache / "blobs"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.work = cache / "work" / f"{version}-{arch}-{os.getpid()}"
        self._registry = self._verified = self._layers = self._facts = self._lock = self._extracted = None
        self._plans = {}

    @property
    def registry(self):
        if self._registry is None:
            self._registry = Registry()
        return self._registry

    def cleanup(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def verified(self):
        if self._verified:
            return self._verified
        registry, version, arch = self.registry, self.version, self.arch
        info(f"Resolving {REGISTRY}/{REPOSITORY}:{version}")
        raw_index, index_digest, index = resolve_index(registry, version)
        image_digest = platform_digest(index, arch)
        for digest in (index_digest, image_digest):
            if digest in BAD_DIGESTS:
                raise BuildError(f"{digest} is a known-compromised image")
        detail(f"index {index_digest}")
        detail(f"linux/{arch} {image_digest}")

        info("Verifying the cosign signature (pinned LiteLLM key, ECDSA P-256)")
        count = verify_cosign(registry, index_digest)
        detail(f"{count} valid signature(s) over {index_digest[:19]}...")
        if shutil.which("cosign"):
            self.work.mkdir(parents=True, exist_ok=True)
            key_file = self.work / "cosign.pub"
            key_file.write_text(COSIGN_PUBLIC_KEY)
            result = subprocess.run(["cosign", "verify", "--key", str(key_file),
                                     f"{REGISTRY}/{REPOSITORY}@{index_digest}"], capture_output=True, text=True)
            if result.returncode != 0:
                raise BuildError("cosign CLI rejected the signature:\n" + result.stderr.strip()[-1500:])
            detail("cosign CLI cross-check passed (incl. transparency log)")

        info("Checking build provenance")
        provenance, revision = check_provenance(registry, index, image_digest)
        official = tag_commit(version)
        if revision != official:
            raise BuildError(f"image was built from commit {revision}, but tag {version} is {official} - DO NOT USE")
        detail(f"built from {EXPECTED_SOURCE} at {revision[:12]} = the commit of tag {version}")
        manifest_body, _ = registry.manifest(image_digest)
        self._verified = {
            "raw_index": raw_index, "index_digest": index_digest, "image_digest": image_digest,
            "manifest_body": manifest_body, "manifest": json.loads(manifest_body), "signatures": count,
            "provenance": provenance, "revision": revision,
        }
        return self._verified

    def evidence(self):
        """Fields every part records about the release it was verified against."""
        v = self.verified()
        return {
            "litellm_version": self.version,
            "platform": f"linux/{self.arch}",
            "source": f"{REGISTRY}/{REPOSITORY}",
            "index_digest": v["index_digest"],
            "platform_digest": v["image_digest"],
            "source_revision": v["revision"],
            "signature": f"cosign, LiteLLM key (pinned): {v['signatures']} valid",
            "provenance": f"{EXPECTED_SOURCE} @ {v['revision'][:12]} (matches tag {self.version})",
        }

    def layers(self):
        """Config + layers in the cache, digest-verified. Returns {digest: path} in manifest order."""
        if self._layers is not None:
            return self._layers
        manifest = self.verified()["manifest"]
        info(f"Image linux/{self.arch} blobs (digest-verified, cached in {self.blobs})")
        self._layers = {}
        for number, desc in enumerate([manifest["config"]] + manifest["layers"]):
            if desc["digest"] in self._layers:
                continue
            label = "config  " if number == 0 else f"layer {number:2d}"
            path = self.blobs / desc["digest"].split(":", 1)[1]
            self.registry.download_blob(desc["digest"], desc["size"], path, label)
            self._layers[desc["digest"]] = path
        return self._layers

    def layer_paths(self):
        paths = self.layers()
        return [paths[desc["digest"]] for desc in self.verified()["manifest"]["layers"]]

    def facts(self):
        """Malware scan of every layer plus the facts the native parts are checked against."""
        if self._facts is not None:
            return self._facts
        manifest, paths = self.verified()["manifest"], self.layers()
        info("Scanning every layer for the 21 Oct payload files")
        hits, pth, unscanned, facts = [], [], 0, {}
        for desc in manifest["layers"]:
            layer_hits, layer_pth = scan_layer(paths[desc["digest"]], desc["mediaType"], facts)
            if layer_hits is None:
                unscanned += 1
                continue
            hits += layer_hits
            pth += layer_pth
        if hits:
            raise BuildError("MALWARE payload files present, do NOT transfer: " + ", ".join(hits))
        detail(f"clean; {len(set(pth))} .pth file(s) in site-packages")
        if unscanned:
            warn(f"{unscanned} zstd layer(s) could not be scanned here; the installer scans the image on the node")
        facts["image_dists"] = sorted(set(facts.get("dists", {}).values()))
        facts["pth"], facts["unscanned"] = sorted(set(pth)), unscanned
        self._facts = facts
        return facts

    def lock_text(self):
        if self._lock is None:
            revision = self.verified()["revision"]
            info(f"Fetching LiteLLM's uv.lock at the verified commit {revision[:12]}")
            self._lock = fetch_text(f"https://raw.githubusercontent.com/BerriAI/litellm/{revision}/uv.lock")
        return self._lock

    def native_plan(self, python):
        """uv.lock resolved for CPython <python>, after the self-check against the image. No wheel downloads."""
        if python in self._plans:
            return self._plans[python]
        try:
            import tomllib
        except ImportError:
            raise BuildError("the native parts (python, litellm) need Python 3.11+ on this PC (tomllib)")
        facts, arch = self.facts(), self.arch
        lock = tomllib.loads(self.lock_text())
        if "image_python" not in facts:
            raise BuildError("could not find LiteLLM's site-packages in the image layers")
        expected = {(n, v) for n, v in facts["image_dists"] if n not in WORKSPACE | NOT_NATIVE}
        image_resolved = resolve_lock(lock, "litellm", NATIVE_EXTRAS, IMAGE_GROUPS, marker_env(facts["image_python"], arch))
        got = {(k, p["version"]) for k, p in image_resolved.items() if k not in WORKSPACE | NOT_NATIVE}
        if got != expected:
            raise BuildError("uv.lock resolution does not reproduce the image's packages "
                             f"(missing {sorted(expected - got)[:5]}, extra {sorted(got - expected)[:5]})")
        self_check = (f"uv.lock resolution for Python {facts['image_python']} reproduced the image's "
                      f"{len(expected)} packages")
        detail("self-check: " + self_check)
        deps = []
        for key, package in sorted(resolve_lock(lock, "litellm", NATIVE_EXTRAS, [], marker_env(python, arch)).items()):
            if key in WORKSPACE or key in NOT_NATIVE:
                continue
            if "registry" not in package.get("source", {}):
                raise BuildError(f"{key} is not from a package index ({package.get('source')})")
            scored = [(wheel_score(w["url"].rsplit("/", 1)[-1], python, arch), w) for w in package.get("wheels", [])]
            scored = [(s, w) for s, w in scored if s]
            if not scored:
                raise BuildError(f"no wheel of {key} {package['version']} fits CPython {python} on linux/{arch}")
            wheel = max(scored, key=lambda item: item[0])[1]
            deps.append({"name": package["name"], "version": package["version"], "url": wheel["url"],
                         "filename": urllib.parse.unquote(wheel["url"].rsplit("/", 1)[-1]),
                         "sha256": wheel["hash"].split(":", 1)[1]})
        requirements = requirements_text((d["name"], d["version"], d["sha256"]) for d in deps)
        plan = {"python": python, "deps": deps, "requirements": requirements, "deps_id": sha256_text(requirements),
                "workspace": {key: image_resolved[key]["version"] for key in sorted(WORKSPACE)},
                "self_check": self_check}
        detail(f"Python {python}: {len(deps)} third-party wheels, dependency set id {plan['deps_id'][:12]}")
        self._plans[python] = plan
        return plan

    def extracted(self):
        """Prisma client/CLI and enterprise hooks copied out of the verified layers (once per run)."""
        if self._extracted:
            return self._extracted
        facts = self.facts()
        if "site_packages" not in facts or "engine_hash" not in facts:
            raise BuildError("could not find the Prisma client and its engine version in the image layers")
        self.work.mkdir(parents=True, exist_ok=True)
        info("Copying the Prisma client/CLI and enterprise hooks out of the verified image")
        engine_re = r"/(query-engine|schema-engine|libquery_engine|prisma-fmt)-[a-z0-9._-]+$"
        out = {"prisma-client.tar": self.work / "prisma-client.tar", "prisma-cli.tar": self.work / "prisma-cli.tar",
               "enterprise.tar": self.work / "enterprise.tar"}
        counts = extract_subtrees(self.layer_paths(), [
            (out["prisma-client.tar"], facts["site_packages"] + "prisma/", "prisma/", r"/__pycache__/"),
            (out["prisma-cli.tar"], "opt/prisma/binaries/node_modules/", "node_modules/", engine_re),
            (out["enterprise.tar"], "app/enterprise/", "enterprise/", r"/__pycache__/"),
        ])
        if not counts[0] or not counts[1]:
            raise BuildError("the image has no Prisma client or CLI where expected")
        detail(f"generated client {counts[0]} files, CLI {counts[1]} files, enterprise hooks {counts[2]} files")
        out["client_id"] = tree_id(out["prisma-client.tar"])
        out["enterprise_id"] = tree_id(out["enterprise.tar"])
        self._extracted = out
        return out


def requirements_text(rows):
    return "".join(f"{name}=={version} --hash=sha256:{digest}\n" for name, version, digest in sorted(rows))


# ============================================================================ parts
PART_KINDS = ("image", "python", "litellm", "prisma", "installer")
PART_GROUPS = {"all": PART_KINDS, "container": ("image", "installer"),
               "native": ("python", "litellm", "prisma", "installer")}
PART_FORMAT = 1
PART_HELP = {
    "image": "signed LiteLLM container image as an OCI archive (container mode)",
    "python": "third-party Python wheels pinned by LiteLLM's uv.lock for the nodes' CPython (native mode)",
    "litellm": "LiteLLM's own wheels (cross-checked against the image) + enterprise hooks (native mode)",
    "prisma": "Prisma generated client + CLI from the image, RHEL query/schema engines (native mode)",
    "installer": "install.py and the guides (runs on its own; finds the other parts)",
}
INSTALLER_FILES = ["install.py", "GUIDE.md", "RUNBOOK.md", "CLUSTER.md", "cluster.py", "cluster_node.py", "build_cluster.py", "build_bundle.py"]


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def part_name(kind, version=None, arch=None, python=None):
    if kind == "installer":
        return "part-installer"
    pieces = ["part", kind, version] + ([f"py{python}"] if python else []) + [arch]
    return "-".join(pieces)


def start_part(parts_dir, name):
    staging = parts_dir / (name + ".partial")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    return staging


def write_checksums(folder, skip_dirs=()):
    lines = []
    for path in sorted(p for p in folder.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        rel = path.relative_to(folder)
        if rel.parts[0] in skip_dirs:
            continue
        lines.append(f"{sha256_file(path)}  {rel.as_posix()}")
    (folder / "SHA256SUMS").write_bytes(("\n".join(lines) + "\n").encode())
    return len(lines)


def finish_part(staging, meta):
    """PART.json + SHA256SUMS, then atomically replace any earlier build of the same part."""
    meta = dict({"format": PART_FORMAT, "created": now_utc(), "builder_os": platform.platform(),
                 "builder_python": platform.python_version()}, **meta)
    (staging / "PART.json").write_text(json.dumps(meta, indent=2) + "\n")
    count = write_checksums(staging)
    final = staging.with_name(meta["name"])
    if final.exists():
        shutil.rmtree(final)
    os.replace(staging, final)
    size = sum(p.stat().st_size for p in final.rglob("*") if p.is_file())
    detail(f"part {meta['name']}: {count} files, {size / 2**20:.0f} MiB")
    return final


def build_image_part(rel, parts_dir):
    info(f"Part 'image' ({PART_HELP['image']})")
    v, paths, facts = rel.verified(), rel.layers(), rel.facts()
    manifest, image_digest = v["manifest"], v["image_digest"]
    name = part_name("image", rel.version, rel.arch)
    staging = start_part(parts_dir, name)
    (staging / "index.json").write_bytes(v["raw_index"])
    (staging / "provenance.json").write_text(v["provenance"], encoding="utf-8")
    (staging / "cosign.pub").write_text(COSIGN_PUBLIC_KEY)
    (staging / "pth-files.txt").write_text("\n".join(facts["pth"]) + "\n")
    local_tag = f"localhost/litellm:{rel.version}"
    archive = staging / f"litellm-{rel.version}-{rel.arch}.oci.tar"
    write_oci_archive(archive, manifest, v["manifest_body"], image_digest, local_tag, rel.arch, rel.blobs, set(paths))
    if shutil.which("trivy"):
        info("Running trivy (HIGH/CRITICAL)")
        scan = subprocess.run(["trivy", "image", "--input", str(archive), "--severity", "HIGH,CRITICAL"],
                              text=True, capture_output=True)
        (staging / "trivy.txt").write_text(scan.stdout + scan.stderr, encoding="utf-8")
        detail("report in trivy.txt")
    meta = dict(rel.evidence(), part="image", name=name, mode="container",
                image_id=manifest["config"]["digest"].split(":", 1)[1], local_tag=local_tag,
                archive=archive.name, archive_format="oci-archive", layers=len(manifest["layers"]),
                compressed_bytes=sum(desc["size"] for desc in manifest["layers"]),
                unscanned_layers=facts["unscanned"])
    return finish_part(staging, meta)


def build_python_part(rel, parts_dir, python):
    info(f"Part 'python' ({PART_HELP['python']})")
    plan = rel.native_plan(python)
    name = part_name("python", rel.version, rel.arch, python)
    staging = start_part(parts_dir, name)
    info(f"Downloading {len(plan['deps'])} wheels (sha256 from uv.lock, cached)")
    total, pth = 0, []
    for dep in plan["deps"]:
        cached, size = cached_fetch(rel.cache, dep["url"], dep["sha256"], dep["filename"])
        total += size or 0
        target = staging / "wheels" / dep["filename"]
        place(cached, target)
        pth += scan_wheel(target)
    detail(f"{len(plan['deps'])} wheels, {total / 2**20:.0f} MiB, all sha256-verified and scanned")
    (staging / "requirements.txt").write_text(plan["requirements"])
    (staging / "uv.lock").write_text(rel.lock_text(), encoding="utf-8")
    (staging / "pth-files.txt").write_text("\n".join(sorted(set(pth))) + "\n")
    meta = dict(rel.evidence(), part="python", name=name, mode="native", python=python,
                deps_id=plan["deps_id"], packages=len(plan["deps"]), requirements="requirements.txt",
                self_check=plan["self_check"],
                note="usable with any litellm part whose requires.deps_id equals deps_id")
    return finish_part(staging, meta)


def build_litellm_part(rel, parts_dir, python):
    info(f"Part 'litellm' ({PART_HELP['litellm']})")
    plan, facts, extracted = rel.native_plan(python), rel.facts(), rel.extracted()
    name = part_name("litellm", rel.version, rel.arch, python)
    staging = start_part(parts_dir, name)
    rows, pth = [], []
    info("Workspace packages from PyPI, cross-checked file-by-file against the verified image")
    for key, version in plan["workspace"].items():
        meta = json.loads(fetch_text(f"https://pypi.org/pypi/{key}/{version}/json"))
        files = [(wheel_score(u["filename"], python, rel.arch), u) for u in meta["urls"]
                 if u["packagetype"] == "bdist_wheel"]
        files = [(s, u) for s, u in files if s]
        if not files:
            raise BuildError(f"no PyPI wheel of {key} {version} fits CPython {python} on linux/{rel.arch}")
        entry = max(files, key=lambda item: item[0])[1]
        cached, _ = cached_fetch(rel.cache, entry["url"], entry["digests"]["sha256"], entry["filename"])
        target = staging / "wheels" / entry["filename"]
        place(cached, target)
        pth += scan_wheel(target)
        with zipfile.ZipFile(target) as wheel:
            record_name = next(n for n in wheel.namelist() if n.endswith(".dist-info/RECORD"))
            wheel_hashes = _record_hashes(wheel.read(record_name).decode())
        image_hashes = _record_hashes(facts.get("image_records", {}).get(key, ""))
        if not image_hashes:
            raise BuildError(f"the image has no RECORD for {key} to compare with")
        python_files = [p for p in wheel_hashes if p.endswith(".py") and not p.startswith(record_name.split("/")[0])]
        mismatched = [p for p in python_files if image_hashes.get(p) != wheel_hashes[p]]
        if mismatched:
            raise BuildError(f"PyPI {entry['filename']} differs from the verified image in {len(mismatched)} "
                             f"Python files, e.g. {mismatched[:3]} - DO NOT USE")
        detail(f"{entry['filename']}: {len(python_files)} Python files identical to the image")
        rows.append((meta["info"]["name"], version, entry["digests"]["sha256"]))
    shutil.copyfile(extracted["enterprise.tar"], staging / "enterprise.tar")
    (staging / "requirements.txt").write_text(requirements_text(rows))
    (staging / "pth-files.txt").write_text("\n".join(sorted(set(pth))) + "\n")
    meta = dict(rel.evidence(), part="litellm", name=name, mode="native", python=python,
                packages=len(rows), requirements="requirements.txt", enterprise="enterprise.tar",
                site_packages_in_image=facts["site_packages"],
                requires={"python": {"deps_id": plan["deps_id"], "packages": len(plan["deps"])},
                          "prisma": {"client_id": extracted["client_id"], "engine_hash": facts["engine_hash"]}})
    return finish_part(staging, meta)


def build_prisma_part(rel, parts_dir):
    info(f"Part 'prisma' ({PART_HELP['prisma']})")
    facts, extracted = rel.facts(), rel.extracted()
    name = part_name("prisma", rel.version, rel.arch)
    staging = start_part(parts_dir, name)
    shutil.copyfile(extracted["prisma-client.tar"], staging / "prisma-client.tar")
    shutil.copyfile(extracted["prisma-cli.tar"], staging / "prisma-cli.tar")
    platform_name, engine_hash = ENGINE_PLATFORM[rel.arch], facts["engine_hash"]
    engines = staging / "engines"
    engines.mkdir()
    for engine in ("query-engine", "schema-engine"):
        base = f"https://binaries.prisma.sh/all_commits/{engine_hash}/{platform_name}/{engine}.gz"
        digest = fetch_text(base + ".sha256").split()[0]
        cached, _ = cached_fetch(rel.cache, base, digest, f"{engine}-{platform_name}.gz")
        with gzip.open(cached, "rb") as source, open(engines / f"{engine}-{platform_name}", "wb") as target:
            shutil.copyfileobj(source, target)
        detail(f"{engine}-{platform_name} ({engine_hash[:12]}), sha256 verified")
    meta = dict(rel.evidence(), part="prisma", name=name, mode="native", client_id=extracted["client_id"],
                engine_hash=engine_hash, engine_platform=platform_name,
                prisma_cli_version=facts.get("prisma_cli_version"),
                note="usable with any litellm part whose requires.prisma matches client_id and engine_hash")
    return finish_part(staging, meta)


EMBED_START = "# ---- embedded downloader (generated from build_bundle.py by build_bundle.py; do not edit) ----\n"
EMBED_END = "# ---- end of embedded downloader ----\n"


def embed_builder(installer_text):
    """Put this downloader (compressed) into install.py, so install.py alone can download parts."""
    start, end = installer_text.find(EMBED_START), installer_text.find(EMBED_END)
    if start < 0 or end < start:
        raise BuildError("install.py has no embedded-downloader block")
    data = (HERE / "build_bundle.py").read_bytes().replace(b"\r\n", b"\n")
    packed = base64.b64encode(zlib.compress(data, 9)).decode()
    lines = "".join(f'    "{packed[i:i + 100]}",\n' for i in range(0, len(packed), 100))
    block = (EMBED_START + "EMBEDDED_BUILDER = [\n" + lines + "]\n"
             + f'EMBEDDED_BUILDER_SHA256 = "{hashlib.sha256(data).hexdigest()}"\n')
    return installer_text[:start] + block + installer_text[end:]


def build_installer_part(parts_dir):
    info(f"Part 'installer' ({PART_HELP['installer']})")
    name = part_name("installer")
    staging = start_part(parts_dir, name)
    for rel in INSTALLER_FILES:
        # LF line endings whatever git did on Windows
        (staging / rel).write_bytes((HERE / rel).read_bytes().replace(b"\r\n", b"\n"))
    installer = embed_builder((staging / "install.py").read_text())
    (staging / "install.py").write_text(installer, newline="\n")
    match = re.search(r'^INSTALLER_VERSION = "([^"]+)"', installer, re.M)
    meta = {"part": "installer", "name": name, "installer_version": match.group(1) if match else None,
            "files": INSTALLER_FILES}
    return finish_part(staging, meta)


# ============================================================================ packing
def write_tar(folder, tar_path, arcname, bundle=False):
    skip = re.compile(r"^[^/]+/(([^/]+\.tar(\.sha256|\.part)?)|parts/[^/]+\.partial|parts/part-installer)(/|$)")

    def keep(entry):
        # the bundle tar never nests per-part tars, unfinished parts or a second copy of the installer
        return None if bundle and skip.match(entry.name) else _safe_member(entry)

    partial = tar_path.with_name(tar_path.name + ".part")
    with tarfile.open(partial, "w", format=tarfile.PAX_FORMAT) as tar:
        tar.add(str(folder), arcname=arcname, filter=keep)
    os.replace(partial, tar_path)
    digest = sha256_file(tar_path)
    tar_path.with_name(tar_path.name + ".sha256").write_bytes(f"{digest}  {tar_path.name}\n".encode())
    return tar_path


def read_part(folder):
    try:
        return json.loads((folder / "PART.json").read_text())
    except (OSError, ValueError):
        return None


def assemble_bundle(bundle, parts_dir):
    """Bundle folder = the installer part at its root + every other part under parts/."""
    installer = parts_dir / part_name("installer")
    if installer.is_dir():
        for path in installer.iterdir():
            shutil.copyfile(path, bundle / path.name)
    contents = []
    for folder in sorted(parts_dir.iterdir()):
        meta = read_part(folder) if folder.is_dir() else None
        if meta and meta.get("part") != "installer":
            contents.append({k: meta.get(k) for k in ("name", "part", "litellm_version", "platform", "python")})
    bundle_info = {"format": PART_FORMAT, "created": now_utc(), "parts": contents,
                   "installer": (bundle / "install.py").is_file()}
    (bundle / "BUNDLE.json").write_text(json.dumps(bundle_info, indent=2) + "\n")
    return contents


def parse_parts(value):
    wanted = []
    for item in (piece.strip().lower() for piece in value.split(",")):
        if not item:
            continue
        if item in PART_GROUPS:
            wanted += PART_GROUPS[item]
        elif item in PART_KINDS:
            wanted.append(item)
        else:
            raise BuildError(f"unknown part '{item}' - choose from {', '.join(PART_KINDS + tuple(PART_GROUPS))}")
    return [kind for kind in PART_KINDS if kind in wanted]


def latest_release():
    try:
        request = urllib.request.Request("https://api.github.com/repos/BerriAI/litellm/releases/latest",
                                         headers={"Accept": "application/vnd.github+json"})
        with open_url(request, timeout=15) as resp:
            data = json.load(resp)
        return data.get("tag_name"), data.get("published_at")
    except (OSError, ValueError, NetworkError):
        return None, None


def check_version(version):
    if not re.match(r"^v\d+\.\d+\.\d+$", version or ""):
        raise BuildError("pin an exact release tag such as v1.106.2 (never latest / main-stable)")
    if version.lstrip("v") in BAD_VERSIONS:
        raise BuildError(f"{version} is the compromised release")


def build(version, arch, kinds, python="3.12", out_arg=None, cache_arg=None, pack="bundle", keep_cache=True):
    if any(kind != "installer" for kind in kinds):
        check_version(version)
    if not kinds:
        raise BuildError("no parts selected")
    label = f"{version}-{arch}" if version else "installer"
    out = Path(out_arg or f"litellm-ha-bundle-{label}").resolve()
    parts_dir = out / "parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    cache = Path(cache_arg or "litellm-build-cache").resolve()
    info(f"Building parts {', '.join(kinds)} into {out}  (cache {cache})")
    rel = Release(version, arch, cache) if version else None
    built = []
    try:
        for kind in kinds:
            if kind == "image":
                built.append(build_image_part(rel, parts_dir))
            elif kind == "python":
                built.append(build_python_part(rel, parts_dir, python))
            elif kind == "litellm":
                built.append(build_litellm_part(rel, parts_dir, python))
            elif kind == "prisma":
                built.append(build_prisma_part(rel, parts_dir))
            else:
                built.append(build_installer_part(parts_dir))
    finally:
        if rel:
            rel.cleanup()
    if not keep_cache:
        shutil.rmtree(cache, ignore_errors=True)

    info("Packing")
    contents = assemble_bundle(out, parts_dir)
    transfer = []
    if pack in ("parts", "both"):
        for folder in built:
            transfer.append(write_tar(folder, out / (folder.name + ".tar"), folder.name))
    if pack in ("bundle", "both"):
        tar_path = out.with_name(out.name + ".tar")
        transfer.append(write_tar(out, tar_path, out.name, bundle=True))
        detail("the bundle folder holds every part built into it so far, also from earlier runs:")
        for item in contents:
            detail(f"  {item['name']}")
    print("\nParts built in this run:")
    for folder in built:
        meta = read_part(folder)
        extra = ""
        if meta.get("deps_id"):
            extra = f"  deps_id {meta['deps_id'][:12]}"
        elif meta.get("requires"):
            extra = (f"  needs python deps_id {meta['requires']['python']['deps_id'][:12]}, "
                     f"prisma client {meta['requires']['prisma']['client_id'][:12]}")
        elif meta.get("client_id"):
            extra = f"  client {meta['client_id'][:12]}"
        print(f"  {folder.name}{extra}")
    if not transfer:
        print(f"\nFolders ready in {parts_dir} (nothing packed)")
        return
    print("\nTransfer into the airgap (each .tar with its .sha256):")
    for tar_path in transfer:
        print(f"  {tar_path}  ({tar_path.stat().st_size / 2**20:.0f} MiB)")
    print("On a node:  sha256sum -c <file>.tar.sha256, then either extract the bundle and run "
          "'sudo python3 install.py', or run install.py and point it at the tars: "
          "'sudo python3 install.py install --bundle /path/to/tars'")


def main():
    parser = argparse.ArgumentParser(
        description="Download and verify the offline parts for the LiteLLM HA gateway",
        epilog="parts: " + "; ".join(f"{k} = {v}" for k, v in PART_HELP.items())
               + ". Groups: all, container (image,installer), native (python,litellm,prisma,installer).")
    parser.add_argument("--version", help="exact LiteLLM release tag, e.g. v1.106.2")
    parser.add_argument("--parts", default="all",
                        help="comma-separated parts or groups to build (default all)")
    parser.add_argument("--arch", default="amd64", choices=ARCHES, help="CPU architecture of the gateway nodes")
    parser.add_argument("--python", default="3.12", help="CPython version of native mode on the nodes (default 3.12)")
    parser.add_argument("--out", help="output folder (default ./litellm-ha-bundle-<version>-<arch>); "
                                      "parts accumulate in <out>/parts across runs")
    parser.add_argument("--cache", help="download cache reused across runs (default ./litellm-build-cache)")
    parser.add_argument("--pack", default="bundle", choices=("bundle", "parts", "both", "none"),
                        help="bundle = one tar of the whole folder; parts = one tar per part built now; "
                             "both; none = folders only (default bundle)")
    parser.add_argument("--no-tar", action="store_true", help="same as --pack none")
    parser.add_argument("--clean-cache", action="store_true", help="delete the download cache when done")
    parser.add_argument("--proxy", default="auto",
                        help="HTTPS proxy: http://[user:password@]host:port, 'none', or 'auto' (default: "
                             "HTTPS_PROXY, else the system proxy, else what Windows uses via PAC/WPAD)")
    parser.add_argument("--check-network", action="store_true",
                        help="show the proxy settings and test every download host, then exit")
    parser.add_argument("--list-parts", action="store_true", help="describe the parts and exit")
    parser.add_argument("--refresh-installer", action="store_true",
                        help="(development) re-embed this downloader into the install.py next to it, and exit")
    args = parser.parse_args()
    if args.refresh_installer:
        target = HERE / "install.py"
        target.write_text(embed_builder(target.read_text()), newline="\n")
        print(f"embedded the downloader into {target}")
        return 0
    if args.list_parts:
        for kind in PART_KINDS:
            print(f"  {kind:<10} {PART_HELP[kind]}")
        return 0
    setup_proxy(args.proxy)
    if args.check_network:
        code = check_network()
        if os.name == "nt" and args.version is None:
            input("\nPress Enter to close this window ")
        return code
    if not re.match(r"^3\.(1[0-4])$", args.python):
        parser.error("--python must be 3.10-3.14")
    if sys.version_info < (3, 9):
        print("Python 3.9 or newer is required.", file=sys.stderr)
        return 2
    interactive = args.version is None and args.parts == "all"
    code = 0
    try:
        version, kinds = args.version, parse_parts(args.parts)
        if interactive:
            tag, published = latest_release()
            if tag:
                print(f"Latest LiteLLM release on GitHub: {tag} (published {published}).")
                print("Prefer a release that has been out a few days, and check LiteLLM's security advisories.")
            version = input("LiteLLM version to bundle (exact tag, e.g. v1.106.2): ").strip()
            for kind in PART_KINDS:
                print(f"  {kind:<10} {PART_HELP[kind]}")
            kinds = parse_parts(input("Parts to download (comma-separated, or all / container / native) [all]: ")
                                .strip() or "all")
        elif version is None and kinds != ["installer"]:
            raise BuildError("--version is required unless --parts installer")
        build(version, args.arch, kinds, args.python, args.out, args.cache,
              "none" if args.no_tar else args.pack, keep_cache=not args.clean_cache)
    except BuildError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        code = 1
    except (urllib.error.URLError, OSError) as exc:
        print(f"\nERROR: network or file problem: {_explain('the download host', exc)}", file=sys.stderr)
        print("Test the connection with:  py -3.12 build_bundle.py --check-network", file=sys.stderr)
        code = 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        code = 130
    if interactive and os.name == "nt":
        input("\nPress Enter to close this window ")
    return code


if __name__ == "__main__":
    sys.exit(main())
