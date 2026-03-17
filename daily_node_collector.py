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
import chardet
from bs4 import BeautifulSoup

# Config
OUTPUT_DIR = "./collected_nodes/"

# Global state
all_nodes = []
node_sources = {}


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

        try:
            decoded_content = decode_base64(response.text)
            if decoded_content:
                nodes = decoded_content.splitlines()
                return [node.strip() for node in nodes if node.strip()]
        except:
            lines = response.text.splitlines()
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

    deduplicate_nodes()
    final_file = save_nodes()

    print(f"\nTotal nodes: {len(all_nodes)}")
    print(f"End: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    if final_file:
        print(f"\nOutput: {final_file}")
    else:
        print("\nNo nodes collected")


if __name__ == '__main__':
    main()
