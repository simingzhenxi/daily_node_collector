# coding=utf-8
"""
Daily Node Collector
Scrapes free proxy nodes from multiple websites and saves them to a file.
Designed to run as a GitHub Actions scheduled job.
"""
import requests
import re
import time
import os
import base64
import json
import copy
import chardet
import yaml
from bs4 import BeautifulSoup
from urllib.parse import quote, urlencode

# Config
OUTPUT_DIR = "./collected_nodes/"
DATIYA_CLASH_FILE = os.path.join(OUTPUT_DIR, "datiya_incremental_clash.yaml")

# Global state
all_nodes = []
node_sources = {}


def encode_base64_urlsafe(data):
    """Encode text as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8').rstrip('=')


def quote_node_name(name):
    """Percent-encode node names for URI fragments."""
    return quote(str(name), safe='')


def build_query(params):
    """Build a compact query string, skipping empty values."""
    filtered = {}
    for key, value in params.items():
        if value in (None, '', [], {}):
            continue
        if isinstance(value, bool):
            filtered[key] = '1' if value else '0'
        elif isinstance(value, list):
            filtered[key] = ','.join(str(item) for item in value if item not in (None, ''))
        else:
            filtered[key] = str(value)
    return urlencode(filtered, quote_via=quote, safe='/:,;=@')


def get_clash_host(proxy, key):
    """Read host-related fields that may be strings or lists."""
    value = proxy.get(key)
    if isinstance(value, list):
        return ','.join(str(item) for item in value if item not in (None, ''))
    return value


def get_ws_host(ws_opts):
    """Read the Host header from Clash ws-opts."""
    headers = ws_opts.get('headers') if isinstance(ws_opts, dict) else None
    if isinstance(headers, dict):
        return headers.get('Host') or headers.get('host')
    return None


def build_ss_node(proxy):
    """Convert a Clash ss proxy to an ss:// node."""
    method = proxy.get('cipher') or proxy.get('method')
    password = proxy.get('password')
    server = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', '')

    if not all([method, password, server, port]):
        return None

    userinfo = encode_base64_urlsafe(f"{method}:{password}")
    node = f"ss://{userinfo}@{server}:{port}"

    plugin = proxy.get('plugin')
    plugin_opts = proxy.get('plugin-opts')
    if plugin:
        plugin_value = plugin
        if isinstance(plugin_opts, dict) and plugin_opts:
            option_parts = [f"{key}={value}" for key, value in plugin_opts.items()]
            plugin_value = f"{plugin};{';'.join(option_parts)}"
        elif plugin_opts:
            plugin_value = f"{plugin};{plugin_opts}"

        query = build_query({'plugin': plugin_value})
        if query:
            node = f"{node}?{query}"

    if name:
        node = f"{node}#{quote_node_name(name)}"
    return node


def build_trojan_node(proxy):
    """Convert a Clash trojan proxy to a trojan:// node."""
    password = proxy.get('password')
    server = proxy.get('server')
    port = proxy.get('port')
    name = proxy.get('name', '')

    if not all([password, server, port]):
        return None

    ws_opts = proxy.get('ws-opts') or {}
    query = build_query({
        'security': 'tls' if proxy.get('tls', True) else None,
        'type': proxy.get('network'),
        'sni': proxy.get('sni'),
        'host': get_ws_host(ws_opts),
        'path': ws_opts.get('path'),
        'alpn': proxy.get('alpn'),
        'allowInsecure': proxy.get('skip-cert-verify'),
    })

    node = f"trojan://{quote(str(password), safe='')}@{server}:{port}"
    if query:
        node = f"{node}?{query}"
    if name:
        node = f"{node}#{quote_node_name(name)}"
    return node


def build_vmess_node(proxy):
    """Convert a Clash vmess proxy to a vmess:// node."""
    server = proxy.get('server')
    port = proxy.get('port')
    uuid = proxy.get('uuid')
    name = proxy.get('name', '')

    if not all([server, port, uuid]):
        return None

    network = proxy.get('network', 'tcp')
    ws_opts = proxy.get('ws-opts') or {}
    h2_opts = proxy.get('h2-opts') or {}
    grpc_opts = proxy.get('grpc-opts') or {}

    host = get_ws_host(ws_opts) or get_clash_host(h2_opts, 'host') or proxy.get('servername') or proxy.get('sni') or ''
    path = ws_opts.get('path') or grpc_opts.get('grpc-service-name') or h2_opts.get('path') or ''

    payload = {
        'v': '2',
        'ps': str(name),
        'add': str(server),
        'port': str(port),
        'id': str(uuid),
        'aid': str(proxy.get('alterId', 0)),
        'scy': str(proxy.get('cipher', 'auto')),
        'net': str(network),
        'type': str(proxy.get('header-type', 'none')),
        'host': str(host),
        'path': str(path),
        'tls': 'tls' if proxy.get('tls') else '',
    }

    if proxy.get('sni'):
        payload['sni'] = str(proxy.get('sni'))
    if proxy.get('alpn'):
        payload['alpn'] = ','.join(proxy.get('alpn')) if isinstance(proxy.get('alpn'), list) else str(proxy.get('alpn'))
    if proxy.get('client-fingerprint'):
        payload['fp'] = str(proxy.get('client-fingerprint'))

    encoded = base64.b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    ).decode('utf-8')
    return f"vmess://{encoded}"


def build_vless_node(proxy):
    """Convert a Clash vless proxy to a vless:// node."""
    server = proxy.get('server')
    port = proxy.get('port')
    uuid = proxy.get('uuid')
    name = proxy.get('name', '')

    if not all([server, port, uuid]):
        return None

    network = proxy.get('network', 'tcp')
    ws_opts = proxy.get('ws-opts') or {}
    grpc_opts = proxy.get('grpc-opts') or {}
    reality_opts = proxy.get('reality-opts') or {}

    query = build_query({
        'encryption': proxy.get('encryption', 'none'),
        'security': proxy.get('security') or ('tls' if proxy.get('tls') else None),
        'type': network,
        'sni': proxy.get('servername') or proxy.get('sni'),
        'host': get_ws_host(ws_opts),
        'path': ws_opts.get('path'),
        'serviceName': grpc_opts.get('grpc-service-name'),
        'flow': proxy.get('flow'),
        'alpn': proxy.get('alpn'),
        'fp': proxy.get('client-fingerprint'),
        'pbk': reality_opts.get('public-key'),
        'sid': reality_opts.get('short-id'),
        'allowInsecure': proxy.get('skip-cert-verify'),
    })

    node = f"vless://{uuid}@{server}:{port}"
    if query:
        node = f"{node}?{query}"
    if name:
        node = f"{node}#{quote_node_name(name)}"
    return node


def build_hysteria2_node(proxy):
    """Convert a Clash hysteria2 proxy to a hysteria2:// node."""
    server = proxy.get('server')
    port = proxy.get('port')
    password = proxy.get('password') or proxy.get('auth') or proxy.get('auth-str')
    name = proxy.get('name', '')

    if not all([server, port, password]):
        return None

    query = build_query({
        'sni': proxy.get('sni'),
        'insecure': proxy.get('skip-cert-verify'),
        'obfs': proxy.get('obfs'),
        'obfs-password': proxy.get('obfs-password'),
    })

    node = f"hysteria2://{quote(str(password), safe='')}@{server}:{port}"
    if query:
        node = f"{node}?{query}"
    if name:
        node = f"{node}#{quote_node_name(name)}"
    return node


def build_hysteria_node(proxy):
    """Convert a Clash hysteria proxy to a hysteria:// node."""
    server = proxy.get('server')
    port = proxy.get('port')
    auth = proxy.get('auth-str') or proxy.get('auth') or proxy.get('password')
    name = proxy.get('name', '')

    if not all([server, port, auth]):
        return None

    query = build_query({
        'protocol': proxy.get('protocol'),
        'peer': proxy.get('sni'),
        'insecure': proxy.get('skip-cert-verify'),
        'obfs': proxy.get('obfs'),
        'upmbps': proxy.get('up'),
        'downmbps': proxy.get('down'),
    })

    node = f"hysteria://{quote(str(auth), safe='')}@{server}:{port}"
    if query:
        node = f"{node}?{query}"
    if name:
        node = f"{node}#{quote_node_name(name)}"
    return node


def clash_proxy_to_node(proxy):
    """Convert a Clash proxy definition into a share link."""
    if not isinstance(proxy, dict):
        return None

    proxy_type = str(proxy.get('type', '')).lower()
    builders = {
        'ss': build_ss_node,
        'trojan': build_trojan_node,
        'vmess': build_vmess_node,
        'vless': build_vless_node,
        'hysteria2': build_hysteria2_node,
        'hysteria': build_hysteria_node,
    }

    builder = builders.get(proxy_type)
    if not builder:
        print(f"    Unsupported Clash proxy type: {proxy_type or 'unknown'}")
        return None

    try:
        return builder(proxy)
    except Exception as e:
        print(f"    Failed to convert Clash proxy {proxy.get('name', '')}: {e}")
        return None


def parse_clash_config(content):
    """Parse a Clash YAML config and convert proxies to share links."""
    try:
        config = yaml.safe_load(content)
    except Exception as e:
        print(f"    Clash YAML parse failed: {e}")
        return []

    if not isinstance(config, dict):
        return []

    proxies = config.get('proxies')
    if not isinstance(proxies, list):
        return []

    nodes = []
    for proxy in proxies:
        node = clash_proxy_to_node(proxy)
        if node:
            nodes.append(node)

    if nodes:
        print(f"    Parsed Clash YAML proxies: {len(nodes)}")
    return nodes


def looks_like_clash_config(content):
    """Heuristic check for Clash YAML content."""
    return bool(re.search(r'(^|\n)proxies:\s*\n', content))


def get_response_text(response):
    """Decode HTTP response text with a better fallback for missing charsets."""
    for encoding in ('utf-8', 'utf-8-sig'):
        try:
            return response.content.decode(encoding)
        except UnicodeDecodeError:
            continue

    if not response.encoding or response.encoding.lower() == 'iso-8859-1':
        detected = chardet.detect(response.content).get('encoding')
        if detected:
            response.encoding = detected
    return response.text


def fetch_url_text(url, headers=None):
    """Fetch URL content and decode it safely."""
    response = requests.get(url, headers=headers, timeout=60)
    response.raise_for_status()
    return get_response_text(response)


def fetch_clash_config(url, headers=None):
    """Fetch and parse a Clash YAML config."""
    content = fetch_url_text(url, headers=headers)
    config = yaml.safe_load(content)
    if not isinstance(config, dict):
        raise ValueError("Clash config is not a YAML mapping")
    return config


def load_yaml_file(file_path):
    """Load a YAML file if it exists."""
    if not os.path.exists(file_path):
        return None

    with open(file_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    return data if isinstance(data, dict) else None


def dump_yaml_file(file_path, data):
    """Write YAML data to disk."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


def dump_datiya_proxies_file(file_path, data):
    """Write datiya proxies in compact inline YAML style."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    proxies = get_clash_proxies(data)

    with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write("proxies:\n")
        for proxy in proxies:
            inline_yaml = yaml.safe_dump(
                proxy,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=True,
                width=10_000,
            ).strip()
            f.write(f"  - {inline_yaml}\n")


def normalize_proxy_for_dedupe(proxy):
    """Build a stable dedupe key for Clash proxies."""
    normalized = copy.deepcopy(proxy)
    if isinstance(normalized, dict):
        normalized.pop('name', None)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True)


def dedupe_clash_proxies(proxies):
    """Deduplicate Clash proxies while keeping the latest version of each node."""
    unique_proxies = []
    key_to_index = {}
    duplicates = 0

    for proxy in proxies:
        if not isinstance(proxy, dict):
            continue
        key = normalize_proxy_for_dedupe(proxy)
        if key in key_to_index:
            duplicates += 1
            unique_proxies[key_to_index[key]] = proxy
            continue
        key_to_index[key] = len(unique_proxies)
        unique_proxies.append(proxy)

    return unique_proxies, duplicates


def get_clash_proxies(config):
    """Extract proxies from a Clash config-like mapping."""
    if not isinstance(config, dict):
        return []

    proxies = config.get('proxies')
    return proxies if isinstance(proxies, list) else []


def merge_datiya_proxy_lists(existing_config, latest_config):
    """Merge datiya proxies into a single incremental proxies file."""
    combined = []
    combined.extend(get_clash_proxies(existing_config))
    combined.extend(get_clash_proxies(latest_config))

    merged_proxies, duplicates = dedupe_clash_proxies(combined)
    return {'proxies': merged_proxies}, len(merged_proxies), duplicates


def decode_base64(data):
    """Decode base64 encoded content."""
    try:
        decoded_bytes = base64.b64decode(data)
        encoding = chardet.detect(decoded_bytes)['encoding']
        return decoded_bytes.decode(encoding)
    except Exception as e:
        print(f"Base64 decode failed: {e}")
        return None


def process_subscription(url, source_name):
    """Process a subscription URL and extract nodes."""
    print(f"  Processing subscription: {url}")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        response_text = get_response_text(response)

        if looks_like_clash_config(response_text):
            nodes = parse_clash_config(response_text)
            if nodes:
                return nodes

        decoded_content = decode_base64(response_text)
        if decoded_content:
            nodes = decoded_content.splitlines()
            return [node.strip() for node in nodes if node.strip()]

        lines = response_text.splitlines()
        prefixes = ('vmess://', 'trojan://', 'ss://', 'vless://',
                    'hysteria://', 'hysteria2://', 'ssr://')
        return [l.strip() for l in lines if l.strip() and l.startswith(prefixes)]
    except Exception as e:
        print(f"    Failed: {e}")
    return []


def collect_from_cfmem():
    """Collect nodes from cfmem.com."""
    print("\n=== Collecting from cfmem.com ===")
    collected = 0
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.53"
        }

        response = requests.get("https://www.cfmem.com/search/label/free", headers=headers, timeout=60)
        response.raise_for_status()
        print("  Fetched search page")

        soup = BeautifulSoup(response.text, 'html.parser')
        latest_article = soup.find('h2', class_='entry-title')
        if latest_article:
            article_url = latest_article.find('a')['href']
            print(f"  Found latest article: {article_url}")

            article_response = requests.get(article_url, headers=headers, timeout=60)
            article_response.raise_for_status()
            article_soup = BeautifulSoup(article_response.text, 'html.parser')

            sub_url_pattern = r'https?://(?:s3\.)?v2rayse\.com/(?:fs/)?public/\d{8}/\w+\.txt'
            sub_url = None

            target_span = article_soup.find('span', style="background-color:#fff;color:#111;font-size:15px")
            if target_span:
                match = re.search(sub_url_pattern, target_span.text)
                if match:
                    sub_url = match.group()

            if not sub_url:
                for element in article_soup.find_all(['p', 'div', 'span', 'a', 'code']):
                    if element.text:
                        match = re.search(sub_url_pattern, element.text)
                        if match:
                            sub_url = match.group()
                            break

            if sub_url:
                print(f"  Subscription URL: {sub_url}")
                nodes = process_subscription(sub_url, 'cfmem.com')
                if nodes:
                    all_nodes.extend(nodes)
                    collected = len(nodes)
                    for node in nodes:
                        node_sources[node] = sub_url
                    print(f"  cfmem.com: collected {collected} nodes")
            else:
                print("  No subscription URL found")
        else:
            print("  No latest article found")
    except Exception as e:
        print(f"  cfmem.com error: {e}")
    return collected


def collect_from_v2rayshare():
    """Collect nodes from v2rayshare.net."""
    print("\n=== Collecting from v2rayshare.net ===")
    collected = 0
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.53"
        }

        response = requests.get("https://v2rayshare.net/", headers=headers, timeout=60)
        response.raise_for_status()

        article_match = re.search(r'https://v2rayshare\.net/p/\d+\.html', response.text)
        if article_match:
            article_url = article_match.group()
            print(f"  Found latest article: {article_url}")

            article_response = requests.get(article_url, headers=headers, timeout=60)
            article_response.raise_for_status()
            article_soup = BeautifulSoup(article_response.text, 'html.parser')

            pattern1 = r'https://v2rayshare\.githubrowcontent\.com/\d{4}/\d{2}/\d{8}\.txt'
            pattern2 = r'https?://[^\s]+\.txt'
            sub_url = None

            target_p = article_soup.find('p', string=re.compile(pattern1))
            if target_p:
                sub_url = target_p.text.strip()
            else:
                for element in article_soup.find_all(['p', 'div', 'span', 'a']):
                    if element.text:
                        match = re.search(pattern2, element.text)
                        if match:
                            sub_url = match.group()
                            break

            if sub_url:
                print(f"  Subscription URL: {sub_url}")
                nodes = process_subscription(sub_url, 'v2rayshare.net')
                if nodes:
                    all_nodes.extend(nodes)
                    collected = len(nodes)
                    for node in nodes:
                        node_sources[node] = sub_url
                    print(f"  v2rayshare.net: collected {collected} nodes")
            else:
                print("  No subscription URL found")
        else:
            print("  No latest article found")
    except Exception as e:
        print(f"  v2rayshare.net error: {e}")
    return collected


def collect_from_nodefree():
    """Collect nodes from nodefree.me."""
    print("\n=== Collecting from nodefree.me ===")
    collected = 0
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.53"
        }

        response = requests.get("https://nodefree.me/", headers=headers, timeout=60)
        response.raise_for_status()

        article_match = re.search(r'https://nodefree\.me/p/\d+\.html', response.text)
        if article_match:
            article_url = article_match.group()
            print(f"  Found latest article: {article_url}")

            article_response = requests.get(article_url, headers=headers, timeout=60)
            article_response.raise_for_status()
            article_soup = BeautifulSoup(article_response.text, 'html.parser')

            pattern1 = r'https://nodefree\.githubrowcontent\.com/\d{4}/\d{2}/\d{8}\.txt'
            pattern2 = r'https?://[^\s]+\.txt'
            sub_url = None

            target_p = article_soup.find('p', string=re.compile(pattern1))
            if target_p:
                sub_url = target_p.text.strip()
            else:
                for element in article_soup.find_all(['p', 'div', 'span', 'a']):
                    if element.text:
                        match = re.search(pattern2, element.text)
                        if match:
                            sub_url = match.group()
                            break

            if sub_url:
                print(f"  Subscription URL: {sub_url}")
                nodes = process_subscription(sub_url, 'nodefree.me')
                if nodes:
                    all_nodes.extend(nodes)
                    collected = len(nodes)
                    for node in nodes:
                        node_sources[node] = sub_url
                    print(f"  nodefree.me: collected {collected} nodes")
            else:
                print("  No subscription URL found")
        else:
            print("  No latest article found")
    except Exception as e:
        print(f"  nodefree.me error: {e}")
    return collected


def collect_from_clashfreenode():
    """Collect nodes from clashfreenode.com."""
    print("\n=== Collecting from clashfreenode.com ===")
    collected = 0
    try:
        date_str = time.strftime('%Y%m%d')
        sub_url = f"https://clashfreenode.com/sub/{date_str}-v2ray.txt"
        print(f"  Generated subscription URL: {sub_url}")

        nodes = process_subscription(sub_url, 'clashfreenode.com')
        if nodes:
            all_nodes.extend(nodes)
            collected = len(nodes)
            for node in nodes:
                node_sources[node] = sub_url
            print(f"  clashfreenode.com: collected {collected} nodes")
        else:
            print("  No nodes found")
    except Exception as e:
        print(f"  clashfreenode.com error: {e}")
    return collected


def collect_from_proxyqueen():
    """Collect nodes from proxyqueen.top."""
    print("\n=== Collecting from proxyqueen.top ===")
    collected = 0
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.53"
        }

        response = requests.get("https://www.proxyqueen.top/", headers=headers, timeout=60)
        response.raise_for_status()

        article_match = re.search(r'https://www\.proxyqueen\.top/index\.php/archives/\d+/', response.text)
        if article_match:
            article_url = article_match.group()
            print(f"  Found latest article: {article_url}")

            article_response = requests.get(article_url, headers=headers, timeout=60)
            article_response.raise_for_status()
            article_soup = BeautifulSoup(article_response.text, 'html.parser')

            pattern = r'https?://[^\s]+-v2ray\.txt'
            sub_url = None
            for element in article_soup.find_all(['p', 'div', 'span', 'a']):
                if element.text:
                    match = re.search(pattern, element.text)
                    if match:
                        sub_url = match.group()
                        break

            if sub_url:
                print(f"  Subscription URL: {sub_url}")
                nodes = process_subscription(sub_url, 'proxyqueen.top')
                if nodes:
                    all_nodes.extend(nodes)
                    collected = len(nodes)
                    for node in nodes:
                        node_sources[node] = sub_url
                    print(f"  proxyqueen.top: collected {collected} nodes")
            else:
                print("  No subscription URL found")
        else:
            print("  No latest article found")
    except Exception as e:
        print(f"  proxyqueen.top error: {e}")
    return collected


def collect_from_datiya():
    """Collect datiya Clash YAML and update the incremental proxies file."""
    print("\n=== Collecting from free.datiya.com ===")
    try:
        date_str = time.strftime('%Y%m%d')
        article_url = f"https://free.datiya.com/post/{date_str}/"
        sub_url = f"https://free.datiya.com/uploads/{date_str}-clash.yaml"

        print(f"  Latest article candidate: {article_url}")
        print(f"  Generated config URL: {sub_url}")

        latest_config = fetch_clash_config(sub_url)
        latest_proxies = get_clash_proxies(latest_config)
        if not latest_proxies:
            print("  No proxies found in YAML")
            return None

        existing_config = load_yaml_file(DATIYA_CLASH_FILE)
        merged_config, merged_count, duplicates = merge_datiya_proxy_lists(existing_config, latest_config)
        dump_datiya_proxies_file(DATIYA_CLASH_FILE, merged_config)

        print(f"  free.datiya.com: today's proxies {len(latest_proxies)}")
        print(f"  free.datiya.com: deduplicated {duplicates} repeated proxies")
        print(f"  free.datiya.com: merged total {merged_count} proxies")
        print(f"  Saved incremental Clash proxies to {DATIYA_CLASH_FILE}")
        return DATIYA_CLASH_FILE
    except Exception as e:
        print(f"  free.datiya.com error: {e}")
    return None


def deduplicate_nodes():
    """Remove duplicate nodes."""
    global all_nodes
    before = len(all_nodes)
    all_nodes = list(set(all_nodes))
    print(f"\nDeduplicated: {before} -> {len(all_nodes)} nodes")


def save_nodes():
    """Save collected nodes to file."""
    if not all_nodes:
        print("No nodes to save")
        return None

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    date_str = time.strftime('%Y%m%d')
    time_str = time.strftime('%H%M%S')
    filename = f"{OUTPUT_DIR}nodes_{date_str}_{time_str}.txt"

    with open(filename, 'w', encoding='utf-8') as f:
        for node in all_nodes:
            source = node_sources.get(node, '')
            f.write(f"{node}#SOURCE#{source}\n")

    print(f"Saved to {filename}")
    return filename


def main():
    print("====== Daily Node Collector ======")
    print(f"Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    collect_from_cfmem()
    collect_from_v2rayshare()
    collect_from_nodefree()
    collect_from_proxyqueen()
    collect_from_clashfreenode()
    datiya_file = collect_from_datiya()

    deduplicate_nodes()
    final_file = save_nodes()

    print(f"\nTotal nodes: {len(all_nodes)}")
    print(f"End: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    if final_file:
        print(f"\nOutput: {final_file}")
    else:
        print("\nNo nodes collected")

    if datiya_file:
        print(f"Datiya Clash proxies: {datiya_file}")


if __name__ == '__main__':
    main()
