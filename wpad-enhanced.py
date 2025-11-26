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

# === PAC template (Simplified) ===
PAC_HEADER = """function FindProxyForURL(url, host) {{
    // QUICK DOMAIN MATCHES
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
    
    // IPv6 DIRECT (String Match)
    if (ip.indexOf(":") !== -1) {{
        if (
{ipv6_direct_rules}
        ) {{
            return "DIRECT";
        }}
    }}

    // IPv4 PROXY
    if (
{ipv4_proxy_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    // IPv6 PROXY (String Match)
    if (ip.indexOf(":") !== -1) {{
        if (
{ipv6_proxy_rules}
        ) {{
            return "HTTPS proxy.iconicompany.com:3129";
        }}
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
            try:
                ip = ipaddress.ip_address(c)
                if isinstance(ip, ipaddress.IPv4Address):
                    v4_set.add(str(ip) + "/32")
                else:
                    v6_set.add(str(ip) + "/128")
            except Exception:
                continue
                
    v4 = sorted(v4_set, key=lambda x: (ipaddress.ip_network(x).network_address.packed, ipaddress.ip_network(x).prefixlen))
    v6 = sorted(v6_set, key=lambda x: (ipaddress.ip_network(x).network_address.packed, ipaddress.ip_network(x).prefixlen))
    return v4, v6

def aggregate_cidrs(cidrs: List[str], mask_limit: int, is_ipv6: bool) -> List[str]:
    """
    Aggregates CIDRs to a higher level (shorter prefix).
    Example: if mask_limit is 32 (for IPv6), 2606:4700:1::/48 becomes 2606:4700::/32
    """
    if mask_limit is None:
        return cidrs

    agg_set = set()
    for c in cidrs:
        try:
            if is_ipv6:
                net = ipaddress.IPv6Network(c, strict=False)
            else:
                net = ipaddress.IPv4Network(c, strict=False)

            # If network is smaller (prefixlen > limit), aggregate it up
            if net.prefixlen > mask_limit:
                new_net = ipaddress.ip_network(f"{net.network_address}/{mask_limit}", strict=False)
                agg_set.add(str(new_net))
            else:
                agg_set.add(str(net))
        except Exception:
            continue
            
    # Sort
    key_func = lambda x: (ipaddress.ip_network(x).network_address.packed, ipaddress.ip_network(x).prefixlen)
    return sorted(list(agg_set), key=key_func)

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
    return [
        "76.76.21.21/32",
        "76.223.126.88/32",
        "13.248.155.104/32",
    ]

def fetch_aws_cloudfront() -> List[str]:
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    data = fetch_url_json(url, cache_name="aws_ip_ranges")
    if not data:
        return []
    prefixes = [p['ip_prefix'] for p in data.get('prefixes', []) if p.get('service') == 'CLOUDFRONT']
    prefixes += [p['ipv6_prefix'] for p in data.get('ipv6_prefixes', []) if p.get('service') == 'CLOUDFRONT']
    return prefixes

# === PAC generators helpers ===
def generate_sh_expmatch_list(domains):
    if not domains:
        return []
    return [f'        shExpMatch(host, "(*.|){d}")' for d in domains]

def generate_ipv4_rule(cidr: str) -> str:
    net = ipaddress.IPv4Network(cidr)
    return f'        isInNet(ip, "{net.network_address}", "{net.netmask}")'

def generate_ipv6_string_rule(cidr: str) -> str:
    """
    Generates a simple string match for IPv6.
    Example: 2606:4700::/32 -> ip.indexOf("2606:4700:") === 0
    """
    try:
        net = ipaddress.IPv6Network(cidr)
        # Convert network address to compressed string (e.g., '2606:4700::')
        compressed = str(net.network_address)
        
        # Determine the safe substring prefix based on mask.
        # This is a heuristic. We want to stop at the colon that covers the mask.
        # /16 = 1 chunk (xxxx:)
        # /32 = 2 chunks (xxxx:xxxx:)
        # /48 = 3 chunks (xxxx:xxxx:xxxx:)
        
        parts = compressed.split(':')
        
        # Calculate how many 16-bit blocks are fully covered by the prefix
        blocks_covered = net.prefixlen // 16
        if blocks_covered < 1: 
            blocks_covered = 1 # Safety fallback
        
        # Reconstruct the prefix string with a trailing colon
        # Handle cases where '::' creates empty parts
        full_parts = net.exploded.split(':') # fully expanded to avoid '::' confusion for slicing
        
        prefix_parts = full_parts[:blocks_covered]
        
        # Re-compress these parts if possible, but simplest is just join with ':' and ensure trailing ':'
        # However, to match browser dnsResolve (which returns compressed), we need to be careful.
        # Simple approach: Check the start of the compressed string provided by python, 
        # ensuring it ends with ':'
        
        # Better approach for PAC:
        # Just use the exploded parts for the prefix, stripping leading zeros is hard in JS regex without regex.
        # Let's rely on the Python 'compressed' output but ensure we strip the '::' if it's at the end
        # and match strictly.
        
        clean_prefix = compressed.split("::")[0]
        if not clean_prefix.endswith(':'):
            clean_prefix += ':'
            
        # Refinement: If mask is very specific (like /128), string match is full match
        if net.prefixlen == 128:
             return f'        ip === "{compressed}"'
             
        return f'        ip.indexOf("{clean_prefix}") === 0'
    except:
        return "false"

def build_pac(direct_domains: List[str], proxy_domains: List[str],
              ipv4_direct: List[str], ipv6_direct: List[str],
              ipv4_proxy: List[str], ipv6_proxy: List[str]) -> str:
    
    direct_domain_str = " ||\n".join(generate_sh_expmatch_list(direct_domains)) or "false"
    proxy_domain_str = " ||\n".join(generate_sh_expmatch_list(proxy_domains)) or "false"
    
    ipv4_direct_str = " ||\n".join([generate_ipv4_rule(c) for c in ipv4_direct]) or "false"
    ipv6_direct_str = " ||\n".join([generate_ipv6_string_rule(c) for c in ipv6_direct]) or "false"
    
    ipv4_proxy_str = " ||\n".join([generate_ipv4_rule(c) for c in ipv4_proxy]) or "false"
    ipv6_proxy_str = " ||\n".join([generate_ipv6_string_rule(c) for c in ipv6_proxy]) or "false"

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
    from dotenv import load_dotenv
    load_dotenv()

    proxy_domains = [d.strip() for d in os.getenv("PROXY_DOMAINS", "").split(",") if d.strip()]
    direct_domains = [d.strip() for d in os.getenv("PROXY_DIRECT_DOMAINS", "").split(",") if d.strip()]
    
    ipv4_direct_env = [c.strip() for c in os.getenv("PROXY_DIRECT_IPV4", "").split(",") if c.strip()]
    ipv6_direct_env = [c.strip() for c in os.getenv("PROXY_DIRECT_IPV6", "").split(",") if c.strip()]
    
    # Settings for aggregation
    # IPv4 default /16 implies taking first 2 bytes
    ipv4_mask_str = os.getenv("IPV4_MASK", "/16").strip() 
    ipv4_mask_int = int(ipv4_mask_str.replace('/', '')) if ipv4_mask_str else None
    
    # IPv6 default /32 implies taking first 2 groups (e.g. 2606:4700)
    # This heavily reduces list size for AWS/Cloudflare
    ipv6_mask_str = os.getenv("IPV6_MASK", "/32").strip()
    ipv6_mask_int = int(ipv6_mask_str.replace('/', '')) if ipv6_mask_str else None

    # === Fetch proxy networks ===
    all_proxy_prefixes: List[str] = []
    all_proxy_prefixes += fetch_cloudflare_ips('v4')
    all_proxy_prefixes += fetch_cloudflare_ips('v6')
    all_proxy_prefixes += fetch_vercel_ips()
    all_proxy_prefixes += fetch_aws_cloudfront()

    # Step 1: Normalize (dedupe raw)
    ipv4_proxy_list, ipv6_proxy_list = normalize_cidrs(all_proxy_prefixes)

    # Step 2: Aggregate (Apply masks)
    if ipv4_mask_int:
        print(f"Aggregating IPv4 to max {ipv4_mask_str}...")
        ipv4_proxy_list = aggregate_cidrs(ipv4_proxy_list, ipv4_mask_int, is_ipv6=False)
        
    if ipv6_mask_int:
        print(f"Aggregating IPv6 to max {ipv6_mask_str} (Simplified String Match)...")
        ipv6_proxy_list = aggregate_cidrs(ipv6_proxy_list, ipv6_mask_int, is_ipv6=True)

    # Normalize direct lists
    ipv4_direct_norm, ipv6_direct_norm = normalize_cidrs(ipv4_direct_env + ipv6_direct_env)

    print(f"Final Counts -> IPv4: {len(ipv4_proxy_list)}, IPv6: {len(ipv6_proxy_list)}")

    pac = build_pac(direct_domains, proxy_domains, ipv4_direct_norm, ipv6_direct_norm, ipv4_proxy_list, ipv6_proxy_list)
    
    out = Path('wpad-enhanced.dat')
    out.write_text(pac)
    print(f"wpad.dat generated: {out.resolve()}")

if __name__ == '__main__':
    main()
