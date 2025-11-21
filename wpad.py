import ipaddress
import requests
import os
from dotenv import load_dotenv

# === Заголовок PAC-файла ===
PAC_HEADER = """function FindProxyForURL(url, host) {{

    // ====================================================
    // 1. ПРОВЕРКА ДОМЕНОВ (Строковые операции, быстро)
    // ====================================================

    // 1.1. DIRECT Exception Domains (Исключения)
    if (
{direct_domain_rules}
    ) {{
        return "DIRECT";
    }}

    // 1.2. Proxy Domains (Явный список для прокси)
    if (
{domain_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    // ====================================================
    // 2. РЕЗОЛВ IP (Блокирующая операция)
    // Выполняем только если домены не совпали
    // ====================================================
    var ip = dnsResolve(host);

    // Защита от сбоев DNS
    if (!ip || (ip.indexOf(".") === -1 && ip.indexOf(":") === -1)) {{
        return "DIRECT";
    }}

    // ====================================================
    // 3. ПРОВЕРКА IP ДЛЯ ПРЯМОГО ДОСТУПА (DIRECT)
    // (IP из .env: локальные сети, VPN и т.д.)
    // ====================================================

    // 3.1. IPv4 DIRECT (Native isInNet)
    if (
{ipv4_direct_rules}
    ) {{
        return "DIRECT";
    }}

    // 3.2. IPv6 DIRECT helpers & check
    // (Функции IPv6 определим ниже, но логика проверки здесь, 
    // если вы используете IPv6 в .env для direct)
    
    // ... (IPv6 logic definition starts here) ...

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
        }} catch (e) {{
            return false;
        }}
    }}

    function inIPv6Range(ipv6, low, high) {{
        if (ipv6.indexOf(":") === -1) return false;
        const ip = parseIPv6(ipv6);
        const lo = parseIPv6(low);
        const hi = parseIPv6(high);
        if (ip === false || lo === false || hi === false) return false;
        return ip >= lo && ip <= hi;
    }}

    // 3.2. IPv6 DIRECT Check
    if (
{ipv6_direct_rules}
    ) {{
        return "DIRECT";
    }}


    // ====================================================
    // 4. ПРОВЕРКА IP ДЛЯ ПРОКСИ (Cloudflare, Vercel)
    // ====================================================

    // 4.1. IPv4 PROXY
    if (
{ipv4_proxy_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    // 4.2. IPv6 PROXY
    if (
{ipv6_proxy_rules}
    ) {{
        return "HTTPS proxy.iconicompany.com:3129";
    }}

    // По умолчанию
    return "DIRECT";
}}
"""

# === Загрузка Cloudflare IP ===
def fetch_cloudflare_ips(version="v4"):
    url = f"https://www.cloudflare.com/ips-{version}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text.strip().splitlines()
    except requests.RequestException as e:
        print(f"⚠️ Ошибка при загрузке IP Cloudflare ({version}): {e}")
        return []

# === Загрузка IP Vercel ===
def fetch_vercel_ips():
    ips = set([
        "76.76.21.21",
        "13.248.155.104",
        "76.223.126.88"
    ])
    return sorted(ips)

# === Генераторы правил ===

def generate_sh_expmatch_list(domains):
    if not domains:
        return []
    return [f'        shExpMatch(host, "(*.|){d}")' for d in domains]

def generate_ipv4_rule(cidr):
    net = ipaddress.IPv4Network(cidr)
    return f'        isInNet(ip, "{net.network_address}", "{net.netmask}")'

def generate_ipv6_rule(cidr):
    net = ipaddress.IPv6Network(cidr)
    start = net.network_address
    end = net.broadcast_address
    return f'        inIPv6Range(ip, "{start}", "{end}")'

def generate_pac(
    direct_domains, proxy_domains, 
    ipv4_direct, ipv6_direct,
    ipv4_proxy, ipv6_proxy
):
    # 1. Домены (Direct и Proxy)
    direct_domain_str = " ||\n".join(generate_sh_expmatch_list(direct_domains)) or "false"
    proxy_domain_str = " ||\n".join(generate_sh_expmatch_list(proxy_domains)) or "false"

    # 2. IP Direct (из .env)
    ipv4_direct_str = " ||\n".join([generate_ipv4_rule(c) for c in ipv4_direct]) or "false"
    ipv6_direct_str = " ||\n".join([generate_ipv6_rule(c) for c in ipv6_direct]) or "false"

    # 3. IP Proxy (Cloudflare, Vercel)
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

# === Основной запуск ===
if __name__ == "__main__":
    load_dotenv()

    # --- 1. Списки Доменов ---
    proxy_domains = [d.strip() for d in os.getenv("PROXY_DOMAINS", "").split(",") if d.strip()]
    direct_domains = [d.strip() for d in os.getenv("PROXY_DIRECT_DOMAINS", "").split(",") if d.strip()]

    # --- 2. Списки IP DIRECT (из .env) ---
    ipv4_direct_env = [c.strip() for c in os.getenv("PROXY_DIRECT_IPV4", "").split(",") if c.strip()]
    ipv6_direct_env = [c.strip() for c in os.getenv("PROXY_DIRECT_IPV6", "").split(",") if c.strip()]

    # --- 3. Списки IP PROXY (Внешние сервисы) ---
    # Cloudflare
    ipv4_proxy_list = fetch_cloudflare_ips("v4")
    ipv6_proxy_list = fetch_cloudflare_ips("v6")
    
    # Vercel (добавляем только к Proxy списку)
    vercel_ips = fetch_vercel_ips()
    ipv4_proxy_list.extend(vercel_ips)

    print(f"📌 DIRECT Domains: {direct_domains}")
    print(f"📌 PROXY Domains: {proxy_domains}")
    print("-" * 30)
    print(f"📌 DIRECT IPv4 (.env): {ipv4_direct_env}")
    print(f"📌 DIRECT IPv6 (.env): {ipv6_direct_env}")
    print("-" * 30)
    print(f"📌 PROXY IPv4 (CF+Vercel): {len(ipv4_proxy_list)} подсетей")
    print(f"📌 PROXY IPv6 (CF): {len(ipv6_proxy_list)} подсетей")

    # Генерация
    pac_script = generate_pac(
        direct_domains, proxy_domains,
        ipv4_direct_env, ipv6_direct_env,
        ipv4_proxy_list, ipv6_proxy_list
    )

    with open("wpad.dat", "w") as f:
        f.write(pac_script)

    print("🎉 PAC-файл wpad.dat успешно создан. Списки IP корректно разделены.")
