import os
import sys
import json
import time
import ipaddress
from pathlib import Path
from typing import List, Tuple, Set

try:
    import requests
except ImportError:
    print("Please pip install requests")
    raise

CACHE_DIR = Path('./cache')
CACHE_DIR.mkdir(exist_ok=True)
CACHE_TTL = 60 * 60 * 24  # 24 hours

# === PAC template ===
PAC_HEADER = """function FindProxyForURL(url, host) {{

    // QUICK DOMAIN MATCHES (string operations)
    if (
{direct_domain_rules}
    ) {{
        return "DIRECT";
    }}

    if (
{domain_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    var ip = dnsResolve(host);
    if (!ip || (ip.indexOf(".") === -1 && ip.indexOf(":" ) === -1)) {{
        return "DIRECT";
    }}

    // IPv4 DIRECT
    if (
{ipv4_direct_rules}
    ) {{
        return "DIRECT";
    }}

    // IPv6 helpers
    function expandIPv6(ipv6) {{
        if (ipv6.indexOf("::") !== -1) {{
            const parts = ipv6.split("::");
            const left = parts[0] ? parts[0].split(":") : [];
            const right = parts[1] ? parts[1].split(":") : [];
            const fill = new Array(8 - left.length - right.length).fill("0");
            ipv6 = [...left, ...fill, ...right].join(":");
        }}
        return ipv6;
    }}

    function parseIPv6(ipv6) {{
        try {{
            const full = expandIPv6(ipv6).split(":");
            if (full.length !== 8) return false;
            let hex = "";
            for (let part of full) {{
                hex += part.padStart(4, "0");
            }}
            return BigInt("0x" + hex);
        }} catch (e) {{ return false; }}
    }}

    function inIPv6Range(ipv6, low, high) {{
        if (ipv6.indexOf(":") === -1) return false;
        const ip = parseIPv6(ipv6);
        const lo = parseIPv6(low);
        const hi = parseIPv6(high);
        if (ip === false || lo === false || hi === false) return false;
        return ip >= lo && ip <= hi;
    }}

    // IPv6 DIRECT
    if (
{ipv6_direct_rules}
    ) {{
        return "DIRECT";
    }}

    // IPv4 PROXY
    if (
{ipv4_proxy_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    // IPv6 PROXY
    if (
{ipv6_proxy_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    return "DIRECT";
}}
"""

# === Helpers ===

def cache_get(name: str):
    p = CACHE_DIR / f"{name}.json"
    if not p.exists():
        return None
    try:
        mtime = p.stat().st_mtime
        if time.time() - mtime > CACHE_TTL:
            return None
        return json.loads(p.read_text())
    except Exception:
        return None


def cache_set(name: str, obj):
    p = CACHE_DIR / f"{name}.json"
    p.write_text(json.dumps(obj))


# normalize and dedupe CIDRs
def normalize_cidrs(cidrs: List[str]) -> Tuple[List[str], List[str]]:
    v4_set: Set[str] = set()
    v6_set: Set[str] = set()
    for c in cidrs:
        c = c.strip()
        if not c:
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4_set.add(str(net.with_prefixlen))
            else:
                v6_set.add(str(net.with_prefixlen))
        except Exception:
            # try to parse bare IP
            try:
                ip = ipaddress.ip_address(c)
                if isinstance(ip, ipaddress.IPv4Address):
                    v4_set.add(str(ip) + "/32")
                else:
                    v6_set.add(str(ip) + "/128")
            except Exception:
                continue
    # sort
    v4 = sorted(v4_set, key=lambda x: (ipaddress.ip_network(x).network_address.packed, ipaddress.ip_network(x).prefixlen))
    v6 = sorted(v6_set, key=lambda x: (ipaddress.ip_network(x).network_address.packed, ipaddress.ip_network(x).prefixlen))
    return v4, v6


# === Fetchers ===

def fetch_url_json(url: str, cache_name: str = None):
    if cache_name:
        cached = cache_get(cache_name)
        if cached is not None:
            return cached
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if cache_name:
            cache_set(cache_name, data)
        return data
    except Exception as e:
        print(f"Failed to fetch JSON {url}: {e}")
        return None


def fetch_text(url: str, cache_name: str = None):
    if cache_name:
        cached = cache_get(cache_name)
        if cached is not None:
            return "\n".join(cached)
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        text = resp.text
        if cache_name:
            cache_set(cache_name, text.splitlines())
        return text
    except Exception as e:
        print(f"Failed to fetch text {url}: {e}")
        return None


def fetch_cloudflare_ips(version='v4') -> List[str]:
    url = f"https://www.cloudflare.com/ips-{version}"
    text = fetch_text(url, cache_name=f"cloudflare_{version}")
    if not text:
        return []
    return [l.strip() for l in text.splitlines() if l.strip()]


def fetch_vercel_ips() -> List[str]:
    # Vercel does not publish a single canonical list; include known edge IPs and prefixes
    # Keep a small static list as fallback
    return [
        "76.76.21.21/32",
        "76.223.126.88/32",
        "13.248.155.104/32",
    ]

def fetch_google_ips() -> List[str]:
    url = "https://www.gstatic.com/ipranges/goog.json"
    data = fetch_url_json(url, cache_name="google_ipranges")
    if not data:
        return []
    prefixes = [p.get('ipv4Prefix') for p in data.get('prefixes', []) if p.get('ipv4Prefix')]
    prefixes += [p.get('ipv6Prefix') for p in data.get('prefixes', []) if p.get('ipv6Prefix')]
    return prefixes


def fetch_aws_cloudfront() -> List[str]:
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    data = fetch_url_json(url, cache_name="aws_ip_ranges")
    if not data:
        return []
    prefixes = [p['ip_prefix'] for p in data.get('prefixes', []) if p.get('service') == 'CLOUDFRONT']
    prefixes += [p['ipv6_prefix'] for p in data.get('ipv6_prefixes', []) if p.get('service') == 'CLOUDFRONT']
    return prefixes


# === PAC generators helpers ===

def generate_sh_expmatch_list(domains: List[str]) -> List[str]:
    if not domains:
        return []
    out = []
    for d in domains:
        d = d.strip()
        if not d:
            continue
        # handle wildcard leading
        if d.startswith("*."):
            dom = d[2:]
            out.append(f'        shExpMatch(host, "*.{dom}")')
            out.append(f'        shExpMatch(host, "{dom}")')
        else:
            out.append(f'        shExpMatch(host, "{d}")')
    return out


def generate_ipv4_rule(cidr: str) -> str:
    net = ipaddress.IPv4Network(cidr)
    return f'        isInNet(ip, "{net.network_address}", "{net.netmask}")'


def generate_ipv6_rule(cidr: str) -> str:
    net = ipaddress.IPv6Network(cidr)
    start = net.network_address
    end = net.broadcast_address
    return f'        inIPv6Range(ip, "{start}", "{end}")'


def build_pac(direct_domains: List[str], proxy_domains: List[str],
              ipv4_direct: List[str], ipv6_direct: List[str],
              ipv4_proxy: List[str], ipv6_proxy: List[str]) -> str:

    direct_domain_str = " ||\n".join(generate_sh_expmatch_list(direct_domains)) or "false"
    proxy_domain_str = " ||\n".join(generate_sh_expmatch_list(proxy_domains)) or "false"

    ipv4_direct_str = " ||\n".join([generate_ipv4_rule(c) for c in ipv4_direct]) or "false"
    ipv6_direct_str = " ||\n".join([generate_ipv6_rule(c) for c in ipv6_direct]) or "false"

    ipv4_proxy_str = " ||\n".join([generate_ipv4_rule(c) for c in ipv4_proxy]) or "false"
    ipv6_proxy_str = " ||\n".join([generate_ipv6_rule(c) for c in ipv6_proxy]) or "false"

    return PAC_HEADER.format(
        direct_domain_rules=direct_domain_str,
        domain_rules=proxy_domain_str,
        ipv4_direct_rules=ipv4_direct_str,
        ipv6_direct_rules=ipv6_direct_str,
        ipv4_proxy_rules=ipv4_proxy_str,
        ipv6_proxy_rules=ipv6_proxy_str
    )


# === Main ===

def main():
    # Load environment variables if present
    from dotenv import load_dotenv
    load_dotenv()

    # Domains from env
    proxy_domains = [d.strip() for d in os.getenv("PROXY_DOMAINS", "").split(",") if d.strip()]
    direct_domains = [d.strip() for d in os.getenv("PROXY_DIRECT_DOMAINS", "").split(",") if d.strip()]

    # Direct IPs from env
    ipv4_direct_env = [c.strip() for c in os.getenv("PROXY_DIRECT_IPV4", "").split(",") if c.strip()]
    ipv6_direct_env = [c.strip() for c in os.getenv("PROXY_DIRECT_IPV6", "").split(",") if c.strip()]

    # === Fetch proxy networks ===
    all_proxy_prefixes: List[str] = []

    # Cloudflare
    all_proxy_prefixes += fetch_cloudflare_ips('v4')
    all_proxy_prefixes += fetch_cloudflare_ips('v6')

    # Vercel
    all_proxy_prefixes += fetch_vercel_ips()

    # Google
    #all_proxy_prefixes += fetch_google_ips()

    # AWS CloudFront
    all_proxy_prefixes += fetch_aws_cloudfront()

    # Microsoft
    #all_proxy_prefixes += fetch_microsoft_prefixes()

    # normalize and dedupe
    ipv4_proxy_list, ipv6_proxy_list = normalize_cidrs(all_proxy_prefixes)

    # normalize direct lists
    ipv4_direct_norm, ipv6_direct_norm = normalize_cidrs(ipv4_direct_env + ipv6_direct_env)

    print(f"Fetched proxy networks: {len(ipv4_proxy_list)} IPv4, {len(ipv6_proxy_list)} IPv6")
    print(f"Direct networks (env): {len(ipv4_direct_norm)} IPv4, {len(ipv6_direct_norm)} IPv6")

    pac = build_pac(direct_domains, proxy_domains, ipv4_direct_norm, ipv6_direct_norm, ipv4_proxy_list, ipv6_proxy_list)

    out = Path('wpad_enhanced.dat')
    out.write_text(pac)
    print(f"wpad.dat generated: {out.resolve()}")


if __name__ == '__main__':
    main()
