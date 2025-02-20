import asyncio
import socket
import subprocess
import platform
import requests
import time
import json
import base64
from Crypto.Cipher import AES
import logging
from datetime import datetime
from dns import resolver, reversename
from ipwhois import IPWhois
import psutil
import screeninfo
import os
import sys
import threading
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from urllib.parse import urljoin, urlparse
from requests.exceptions import RequestException
from itertools import cycle
from typing import List, Tuple, Optional, Dict, Any
import uuid
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from tqdm import tqdm
import random
from colorama import Fore, Back, Style, init
import aiohttp
from aiohttp import ClientSession, ClientProxyConnectionError, ClientResponseError
import re
import tldextract

init(autoreset=True)

try:
    nltk.data.find('sentiment/vader_lexicon.zip')
except LookupError:
    nltk.download('vader_lexicon')

ENCRYPTION_KEY = b'SecureKey1234567'
IV_KEY = os.urandom(16)
LOG_FILE = "advanced_ip_tracker_log.txt"
DB_FILE = "ip_tracker.db"
PROXY_LIST_URL = "https://www.sslproxies.org/"
MAX_RETRIES = 5
TIMEOUT = 15
REQUEST_DELAY = 2
MAX_CONCURRENT_REQUESTS = 5

SOCIAL_MEDIA_PLATFORMS = {
    "Twitter": {"url": "https://twitter.com/{}", "check": lambda soup: "Twitter" in soup.title.text},
    "Facebook": {"url": "https://www.facebook.com/{}", "check": lambda soup: "Facebook" in soup.title.text},
    "Instagram": {"url": "https://www.instagram.com/{}", "check": lambda soup: "Instagram" in soup.title.text},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "check": lambda soup: "LinkedIn" in soup.title.text},
    "GitHub": {"url": "https://github.com/{}", "check": lambda soup: "GitHub" in soup.title.text},
    "Reddit": {"url": "https://www.reddit.com/user/{}", "check": lambda soup: "Reddit" in soup.title.text},
    "YouTube": {"url": "https://www.youtube.com/user/{}", "check": lambda soup: "YouTube" in soup.title.text},
    "Pinterest": {"url": "https://www.pinterest.com/{}", "check": lambda soup: "Pinterest" in soup.title.text},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "check": lambda soup: "TikTok" in soup.title.text},
    "Tumblr": {"url": "https://{}.tumblr.com", "check": lambda soup: "Tumblr" in soup.title.text},
    "Snapchat": {"url": "https://www.snapchat.com/add/{}", "check": lambda soup: "Snapchat" in soup.title.text},
    "Vimeo": {"url": "https://vimeo.com/{}", "check": lambda soup: "Vimeo" in soup.title.text},
    "Twitch": {"url": "https://www.twitch.tv/{}", "check": lambda soup: "Twitch" in soup.title.text},
    "Discord": {"url": "https://discord.com/users/{}", "check": lambda soup: "Discord" in soup.title.text},
    "Telegram": {"url": "https://t.me/{}", "check": lambda soup: "Telegram" in soup.title.text},
    "Medium": {"url": "https://medium.com/@{}", "check": lambda soup: "Medium" in soup.title.text},
    "Patreon": {"url": "https://www.patreon.com/{}", "check": lambda soup: "Patreon" in soup.title.text},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "check": lambda soup: "DeviantArt" in soup.title.text},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "check": lambda soup: "SoundCloud" in soup.title.text},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "check": lambda soup: "Spotify" in soup.title.text},
    "Steam": {"url": "https://steamcommunity.com/id/{}", "check": lambda soup: "Steam" in soup.title.text},
    "Xbox Live": {"url": "https://account.xbox.com/en-us/Profile?gamerTag={}", "check": lambda soup: "Xbox" in soup.title.text},
    "PlayStation Network": {"url": "https://psnprofiles.com/{}", "check": lambda soup: "PSN" in soup.title.text},
    "About.me": {"url": "https://about.me/{}", "check": lambda soup: "About.me" in soup.title.text},
    "Gravatar": {"url": "https://en.gravatar.com/{}", "check": lambda soup: "Gravatar" in soup.title.text},
    "Crunchbase": {"url": "https://www.crunchbase.com/{}", "check": lambda soup: "Crunchbase" in soup.title.text},
    "Goodreads": {"url": "https://www.goodreads.com/user/show/{}", "check": lambda soup: "Goodreads" in soup.title.text},
    "Last.fm": {"url": "https://www.last.fm/user/{}", "check": lambda soup: "Last.fm" in soup.title.text},
}

semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

def log(msg: str, level: str = "INFO") -> None:
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.log(getattr(logging, level), f"{timestamp} - {msg}")

def encrypt_data(data: str) -> str:
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV_KEY)
    padded_data = data + (16 - len(data) % 16) * ' '
    encrypted_data = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data: str) -> str:
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, IV_KEY)
    decoded_data = base64.b64decode(encrypted_data)
    decrypted_data = cipher.decrypt(decoded_data).decode('utf-8')
    return decrypted_data.strip()

async def fetch_proxies() -> List[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(PROXY_LIST_URL, timeout=TIMEOUT) as response:
                response.raise_for_status()
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                proxies = []
                table = soup.find('table', id='proxylisttable')
                if table:
                    for row in table.find_all('tr')[1:]:
                        tds = row.find_all('td')
                        try:
                            ip = tds[0].text.strip()
                            port = tds[1].text.strip()
                            proxies.append(f"http://{ip}:{port}")
                        except IndexError:
                            continue
                log(f"Fetched {len(proxies)} proxies.")
                return proxies
    except (RequestException, aiohttp.ClientError) as e:
        log(f"Error fetching proxies: {e}", "ERROR")
        return []

async def is_proxy_working(session: ClientSession, proxy: str) -> bool:
    try:
        async with session.get("https://www.google.com", proxy=proxy, timeout=TIMEOUT) as response:
            return response.status == 200
    except (ClientProxyConnectionError, aiohttp.ClientError):
        return False

async def get_working_proxy(proxies: List[str]) -> Optional[str]:
    async with ClientSession() as session:
        for proxy in proxies:
            if await is_proxy_working(session, proxy):
                log(f"Working proxy found: {proxy}")
                return proxy
        log("No working proxies found.", "WARNING")
        return None

async def fetch_with_retry(session: ClientSession, url: str, retries: int = MAX_RETRIES, proxy: Optional[str] = None, is_json: bool = False) -> Optional[str]:
    for attempt in range(retries):
        try:
            kwargs = {"timeout": TIMEOUT}
            if proxy:
                kwargs["proxy"] = proxy
            async with semaphore:
                async with session.get(url, **kwargs) as response:
                    response.raise_for_status()
                    if is_json:
                        return await response.json()
                    else:
                        return await response.text()
        except (ClientProxyConnectionError, aiohttp.ClientError, ClientResponseError) as e:
            log(f"Error fetching {url} (Attempt {attempt + 1}/{retries}): {e}", "ERROR")
            if attempt == retries - 1:
                log(f"Max retries reached for {url}. Aborting.", "ERROR")
                return None
            await asyncio.sleep(REQUEST_DELAY)
    return None

async def get_public_ip() -> Optional[str]:
    try:
        proxies = await fetch_proxies()
        working_proxy = await get_working_proxy(proxies)
        async with aiohttp.ClientSession() as session:
            data = await fetch_with_retry(session, "https://ipinfo.io/json", proxy=working_proxy, is_json=True)
            if data:
                ip = data.get("ip", "Unavailable")
                log(f"Public IP: {ip}")
                print(f"{Fore.GREEN}Public IP: {ip}{Style.RESET_ALL}")
                return ip
            else:
                print(f"{Fore.RED}Error fetching public IP{Style.RESET_ALL}")
                return None
    except Exception as e:
        log(f"Error fetching public IP: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching public IP: {e}{Style.RESET_ALL}")
        return None

async def get_ip_from_website(website: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, website)
        log(f"IP address of {website}: {ip}")
        print(f"{Fore.GREEN}IP address of {website}: {ip}{Style.RESET_ALL}")
        return ip
    except socket.gaierror as e:
        log(f"Error resolving website to IP: {e}", "ERROR")
        print(f"{Fore.RED}Error resolving website to IP{Style.RESET_ALL}")
        return None

async def dns_lookup(domain: str) -> None:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, resolver.resolve, domain, "A")
        for answer in answers:
            log(f"DNS Record for {domain}: {answer}")
            print(f"{Fore.GREEN}DNS Record for {domain}: {answer}{Style.RESET_ALL}")
    except Exception as e:
        log(f"Error in DNS lookup for {domain}: {e}", "ERROR")
        print(f"{Fore.RED}Error in DNS lookup for {domain}{Style.RESET_ALL}")

async def reverse_dns(ip: str) -> None:
    try:
        loop = asyncio.get_event_loop()
        reverse_name = reversename.from_address(ip)
        answers = await loop.run_in_executor(None, resolver.resolve, reverse_name, "PTR")
        for answer in answers:
            log(f"Reverse DNS for {ip}: {answer.to_text()}")
            print(f"{Fore.GREEN}Reverse DNS for {ip}: {answer.to_text()}{Style.RESET_ALL}")
    except Exception as e:
        log(f"Error in reverse DNS lookup for {ip}: {e}", "ERROR")
        print(f"{Fore.RED}Error in reverse DNS lookup for {ip}{Style.RESET_ALL}")

async def whois_lookup(ip: str) -> Optional[Dict[str, Any]]:
    try:
        loop = asyncio.get_event_loop()
        ipwhois = IPWhois(ip)
        whois_data = await loop.run_in_executor(None, ipwhois.lookup_rdap)

        if whois_data:
            network = whois_data.get('network', {})
            inetnum = network.get('startAddress') + " - " + network.get('endAddress') if network.get('startAddress') and network.get('endAddress') else "N/A"
            netname = network.get('name', "N/A")
            country = network.get('country', "N/A")
            status = network.get('status', "N/A")
            
            entities = whois_data.get('entities', {})
            admin_c = entities.get('admin', ["N/A"])[0] if entities.get('admin') else "N/A"
            tech_c = entities.get('tech', ["N/A"])[0] if entities.get('tech') else "N/A"
            
            whois_info = f"""
            {Fore.GREEN}WHOIS Data for {ip}:{Style.RESET_ALL}
            {Fore.CYAN}inetnum:{Style.RESET_ALL}        {inetnum}
            {Fore.CYAN}netname:{Style.RESET_ALL}        {netname}
            {Fore.CYAN}country:{Style.RESET_ALL}        {country}
            {Fore.CYAN}admin-c:{Style.RESET_ALL}        {admin_c}
            {Fore.CYAN}tech-c:{Style.RESET_ALL}         {tech_c}
            {Fore.CYAN}status:{Style.RESET_ALL}         {status}
            """
            print(whois_info)
            log(f"WHOIS Data for {ip}: \n{whois_info}")
        else:
            print(f"{Fore.RED}No WHOIS data found for {ip}{Style.RESET_ALL}")
            log(f"No WHOIS data found for {ip}", "WARNING")
        return whois_data
    except Exception as e:
        log(f"Error performing WHOIS lookup: {e}", "ERROR")
        print(f"{Fore.RED}Error performing WHOIS lookup{Style.RESET_ALL}")
        return None

async def get_location(ip: str) -> Optional[Dict[str, Any]]:
    try:
        async with aiohttp.ClientSession() as session:
            data = await fetch_with_retry(session, f"https://freegeoip.app/json/{ip}", is_json=True)
            if data:
                country = data.get("country_name", "Unavailable")
                region = data.get("region_name", "Unavailable")
                city = data.get("city", "Unavailable")
                log(f"Location for IP {ip}: {city}, {region}, {country}")
                print(f"{Fore.GREEN}Location for IP {ip}: {city}, {region}, {country}{Style.RESET_ALL}")
                return data
            else:
                print(f"{Fore.RED}Error fetching location for {ip}{Style.RESET_ALL}")
                return None
    except Exception as e:
        log(f"Error fetching location for {ip}: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching location for {ip}{Style.RESET_ALL}")
        return None

async def scan_with_ip_api(ip_or_url: str) -> None:
    try:
        async with aiohttp.ClientSession() as session:
            data = await fetch_with_retry(session, f"https://ipinfo.io/{ip_or_url}/json", is_json=True)
            if data:
                log(f"{ip_or_url} scan result: {json.dumps(data, indent=4)}")
                print(f"{Fore.GREEN}{ip_or_url} scan result: {json.dumps(data, indent=4)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Error scanning {ip_or_url} with ipinfo.io{Style.RESET_ALL}")
    except Exception as e:
        log(f"Error scanning {ip_or_url} with ipinfo.io: {e}", "ERROR")
        print(f"{Fore.RED}Error scanning {ip_or_url} with ipinfo.io{Style.RESET_ALL}")

async def ping_ip(ip: str) -> bool:
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, subprocess.run, ["ping", param, "4", ip], capture_output=True, text=True)
        if "Reply from" in result.stdout or "bytes from" in result.stdout:
            log(f"{ip} is ACTIVE.")
            print(f"{Fore.GREEN}{ip} is ACTIVE.{Style.RESET_ALL}")
            return True
        else:
            log(f"{ip} appears to be INACTIVE.")
            print(f"{Fore.YELLOW}{ip} appears to be INACTIVE.{Style.RESET_ALL}")
            return False
    except Exception as e:
        log(f"Error pinging IP: {e}", "ERROR")
        print(f"{Fore.RED}Error pinging IP{Style.RESET_ALL}")
        return False

async def run_traceroute(ip: str) -> Optional[str]:
    try:
        command = ["tracert", ip] if platform.system().lower() == "windows" else ["traceroute", ip]
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, subprocess.run, command, capture_output=True, text=True)
        log(f"Traceroute for {ip}: \n{result.stdout}")
        print(f"{Fore.GREEN}Traceroute for {ip}: \n{result.stdout}{Style.RESET_ALL}")
        return result.stdout
    except Exception as e:
        log(f"Error running traceroute: {e}", "ERROR")
        print(f"{Fore.RED}Error running traceroute{Style.RESET_ALL}")
        return None

async def port_scan(ip: str) -> List[int]:
    common_ports = [21, 22, 23, 25, 53, 80, 443, 8080]
    open_ports = []
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        log(f"Open Ports on {ip}: {open_ports}")
        print(f"{Fore.GREEN}Open Ports on {ip}: {open_ports}{Style.RESET_ALL}")
        return open_ports
    except Exception as e:
        log(f"Error scanning ports: {e}", "ERROR")
        print(f"{Fore.RED}Error scanning ports{Style.RESET_ALL}")
        return []

def setup_database() -> None:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_logs (
            timestamp TEXT,
            ip_address TEXT,
            event TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_to_database(ip: str, event: str) -> None:
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ip_logs (timestamp, ip_address, event) VALUES (?, ?, ?)",
                   (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, event))
    conn.commit()
    conn.close()

def get_system_info() -> Optional[Dict[str, Any]]:
    try:
        log("Fetching system information...")
        uname = platform.uname()
        cpu_info = psutil.cpu_times()
        memory_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')
        system_info = {
            "System": uname.system,
            "Node Name": uname.node,
            "Release": uname.release,
            "Version": uname.version,
            "Machine": uname.machine,
            "CPU Usage": cpu_info,
            "Memory Usage": memory_info.percent,
            "Disk Usage": disk_info.percent
        }
        log(f"System Info: {json.dumps(system_info, indent=4)}")
        print(f"{Fore.GREEN}System Info: {json.dumps(system_info, indent=4)}{Style.RESET_ALL}")
        return system_info
    except Exception as e:
        log(f"Error fetching system information: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching system information{Style.RESET_ALL}")
        return None

def generate_key() -> None:
    key = os.urandom(32)
    with open("aes_key.key", "wb") as key_file:
        key_file.write(key)

def load_key() -> bytes:
    return open("aes_key.key", "rb").read()

def encrypt_data_scraper(data: bytes) -> bytes:
    key = load_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_data = data + (16 - len(data) % 16) * b' '
    encrypted_data = encryptor.update(pad_data) + encryptor.finalize()

    return iv + encrypted_data

async def fetch_html(url: str, retries: int = 3, proxy: Optional[str] = None) -> Optional[str]:
    headers = {'User-Agent': UserAgent().random}
    async with aiohttp.ClientSession(headers=headers) as session:
        for attempt in range(retries):
            try:
                kwargs = {"timeout": TIMEOUT}
                if proxy:
                    kwargs["proxy"] = proxy
                async with semaphore:
                    async with session.get(url, **kwargs) as response:
                        response.raise_for_status()
                        log(f"Successfully fetched HTML from {url} using proxy {proxy if proxy else 'None'}")
                        return await response.text()
            except (ClientProxyConnectionError, aiohttp.ClientError, ClientResponseError) as e:
                log(f"Error fetching {url} (Attempt {attempt + 1}/{retries}): {e}", "ERROR")
                if attempt == retries - 1:
                    log(f"Max retries reached for {url}. Aborting.", "ERROR")
                    return None
                await asyncio.sleep(REQUEST_DELAY)
    return None

def extract_data_from_html(html: str, base_url: str) -> Tuple[List[str], List[str]]:
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    text_content = []

    for link in soup.find_all('a', href=True):
        href = link['href']
        links.append(urljoin(base_url, href))

    for tag in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span', 'article', 'section', 'footer', 'header', 'nav', 'aside', 'strong', 'em', 'b', 'i', 'u', 'table', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'script', 'style', 'link']):
        if tag.get_text(strip=True):
            text_content.append(tag.get_text(strip=True))

    log(f"Extracted {len(links)} links and {len(text_content)} content pieces.")
    return links, text_content

def save_encrypted_data(data: List[Tuple[str, str]], filename: str = 'scraped_data.csv') -> None:
    try:
        csv_content = "Link,Content\n"
        for row in data:
            csv_content += f"{row[0]},{row[1]}\n"
        encrypted_data = encrypt_data_scraper(csv_content.encode())
        with open(f"encrypted_{filename}", 'wb') as file:
            file.write(encrypted_data)
        log(f"Encrypted data saved to encrypted_{filename}.")
        print(f"{Fore.GREEN}Encrypted data saved to encrypted_{filename}.{Style.RESET_ALL}")
    except Exception as e:
        log(f"Error saving encrypted CSV: {e}", "ERROR")
        print(f"{Fore.RED}Error saving encrypted CSV{Style.RESET_ALL}")

async def scrape_multiple_urls(urls: List[str], total_pages: int = 5) -> List[Tuple[str, str]]:
    all_data = []
    proxies = await fetch_proxies()
    working_proxy = await get_working_proxy(proxies)

    for base_url in urls:
        for page in range(1, total_pages + 1):
            url = f"{base_url}?page={page}" if "?" not in base_url else f"{base_url}&page={page}"
            log(f"Scraping page {page} from {url}")
            html = await fetch_html(url, proxy=working_proxy)
            if html:
                links, text_content = extract_data_from_html(html, base_url)
                page_data = list(zip(links, text_content))
                all_data.extend(page_data)
                log(f"Found {len(page_data)} entries on page {page}.")
            await asyncio.sleep(REQUEST_DELAY)
    return all_data

async def scrape_in_parallel(urls: List[str], total_pages: int = 5, num_threads: int = 3) -> List[Tuple[str, str]]:
    all_data = []
    proxies = await fetch_proxies()
    working_proxy = await get_working_proxy(proxies)

    async def thread_scraper(url_list: List[str], start_idx: int, end_idx: int) -> None:
        nonlocal all_data
        for idx in range(start_idx, end_idx):
            base_url = urls[idx]
            log(f"Starting to scrape {base_url}")
            data = await scrape_multiple_urls([base_url], total_pages=total_pages)
            all_data.extend(data)

    urls_per_thread = len(urls) // num_threads
    tasks = []
    for i in range(num_threads):
        start_idx = i * urls_per_thread
        end_idx = (i + 1) * urls_per_thread if i != num_threads - 1 else len(urls)
        task = asyncio.create_task(thread_scraper(urls, start_idx, end_idx))
        tasks.append(task)

    await asyncio.gather(*tasks)
    return all_data

def reboot_program() -> None:
    log("Rebooting the program...")
    python = sys.executable
    os.execl(python, python, *sys.argv)

def validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")

async def check_open_ports(ip: str, ports: List[int]) -> List[int]:
    open_ports = []
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        log(f"Checked Ports on {ip}: {open_ports}")
        print(f"{Fore.GREEN}Checked Ports on {ip}: {open_ports}{Style.RESET_ALL}")
        return open_ports
    except Exception as e:
        log(f"Error checking ports: {e}", "ERROR")
        print(f"{Fore.RED}Error checking ports{Style.RESET_ALL}")
        return []

def get_cpu_usage() -> float:
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        log(f"CPU Usage: {cpu_usage}%")
        print(f"{Fore.GREEN}CPU Usage: {cpu_usage}%{Style.RESET_ALL}")
        return cpu_usage
    except Exception as e:
        log(f"Error fetching CPU usage: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching CPU usage{Style.RESET_ALL}")
        return 0.0

def get_memory_usage() -> float:
    try:
        memory_info = psutil.virtual_memory()
        log(f"Memory Usage: {memory_info.percent}%")
        print(f"{Fore.GREEN}Memory Usage: {memory_info.percent}%{Style.RESET_ALL}")
        return memory_info.percent
    except Exception as e:
        log(f"Error fetching memory usage: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching memory usage{Style.RESET_ALL}")
        return 0.0

def get_disk_usage() -> float:
    try:
        disk_info = psutil.disk_usage('/')
        log(f"Disk Usage: {disk_info.percent}%")
        print(f"{Fore.GREEN}Disk Usage: {disk_info.percent}%{Style.RESET_ALL}")
        return disk_info.percent
    except Exception as e:
        log(f"Error fetching disk usage: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching disk usage{Style.RESET_ALL}")
        return 0.0

def get_network_info() -> Dict[str, Any]:
    try:
        net_info = psutil.net_if_addrs()
        log(f"Network Info: {json.dumps(net_info, indent=4)}")
        print(f"{Fore.GREEN}Network Info: {json.dumps(net_info, indent=4)}{Style.RESET_ALL}")
        return net_info
    except Exception as e:
        log(f"Error fetching network info: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching network info{Style.RESET_ALL}")
        return {}

def get_screen_resolution() -> Tuple[int, int]:
    try:
        screen = screeninfo.get_monitors()[0]
        resolution = (screen.width, screen.height)
        log(f"Screen Resolution: {resolution}")
        print(f"{Fore.GREEN}Screen Resolution: {resolution}{Style.RESET_ALL}")
        return resolution
    except Exception as e:
        log(f"Error fetching screen resolution: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching screen resolution{Style.RESET_ALL}")
        return (0, 0)

def get_running_processes() -> List[str]:
    try:
        processes = [proc.name() for proc in psutil.process_iter()]
        log(f"Running Processes: {processes}")
        print(f"{Fore.GREEN}Running Processes: {processes}{Style.RESET_ALL}")
        return processes
    except Exception as e:
        log(f"Error fetching running processes: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching running processes{Style.RESET_ALL}")
        return []

def get_installed_packages() -> List[str]:
    try:
        packages = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze']).decode().split('\n')
        log(f"Installed Packages: {packages}")
        print(f"{Fore.GREEN}Installed Packages: {packages}{Style.RESET_ALL}")
        return packages
    except Exception as e:
        log(f"Error fetching installed packages: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching installed packages{Style.RESET_ALL}")
        return []

def get_system_uptime() -> str:
    try:
        uptime_seconds = time.time() - psutil.boot_time()
        uptime_str = str(datetime.timedelta(seconds=uptime_seconds))
        log(f"System Uptime: {uptime_str}")
        print(f"{Fore.GREEN}System Uptime: {uptime_str}{Style.RESET_ALL}")
        return uptime_str
    except Exception as e:
        log(f"Error fetching system uptime: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching system uptime{Style.RESET_ALL}")
        return "Unavailable"

def get_battery_status() -> Dict[str, Any]:
    try:
        battery = psutil.sensors_battery()
        if battery:
            status = {
                "percent": battery.percent,
                "plugged_in": battery.power_plugged
            }
            log(f"Battery Status: {status}")
            print(f"{Fore.GREEN}Battery Status: {status}{Style.RESET_ALL}")
            return status
        else:
            print(f"{Fore.YELLOW}Battery status is not available.{Style.RESET_ALL}")
            return {}
    except Exception as e:
        log(f"Error fetching battery status: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching battery status{Style.RESET_ALL}")
        return {}

def get_temperature_sensors() -> Dict[str, Any]:
    try:
        temps = psutil.sensors_temperatures()
        log(f"Temperature Sensors: {json.dumps(temps, indent=4)}")
        print(f"{Fore.GREEN}Temperature Sensors: {json.dumps(temps, indent=4)}{Style.RESET_ALL}")
        return temps
    except Exception as e:
        log(f"Error fetching temperature sensors: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching temperature sensors{Style.RESET_ALL}")
        return {}

def get_fan_speeds() -> Dict[str, Any]:
    try:
        fans = psutil.sensors_fans()
        log(f"Fan Speeds: {json.dumps(fans, indent=4)}")
        print(f"{Fore.GREEN}Fan Speeds: {json.dumps(fans, indent=4)}{Style.RESET_ALL}")
        return fans
    except Exception as e:
        log(f"Error fetching fan speeds: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching fan speeds{Style.RESET_ALL}")
        return {}

def get_system_architecture() -> str:
    try:
        architecture = platform.architecture()[0]
        log(f"System Architecture: {architecture}")
        print(f"{Fore.GREEN}System Architecture: {architecture}{Style.RESET_ALL}")
        return architecture
    except Exception as e:
        log(f"Error fetching system architecture: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching system architecture{Style.RESET_ALL}")
        return "Unknown"

def get_python_version() -> str:
    try:
        version = platform.python_version()
        log(f"Python Version: {version}")
        print(f"{Fore.GREEN}Python Version: {version}{Style.RESET_ALL}")
        return version
    except Exception as e:
        log(f"Error fetching Python version: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching Python version{Style.RESET_ALL}")
        return "Unknown"

def get_hostname() -> str:
    try:
        hostname = socket.gethostname()
        log(f"Hostname: {hostname}")
        print(f"{Fore.GREEN}Hostname: {hostname}{Style.RESET_ALL}")
        return hostname
    except Exception as e:
        log(f"Error fetching hostname: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching hostname{Style.RESET_ALL}")
        return "Unknown"

def get_ip_addresses() -> List[str]:
    try:
        ip_addresses = socket.gethostbyname_ex(socket.gethostname())[2]
        log(f"IP Addresses: {ip_addresses}")
        print(f"{Fore.GREEN}IP Addresses: {ip_addresses}{Style.RESET_ALL}")
        return ip_addresses
    except Exception as e:
        log(f"Error fetching IP addresses: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching IP addresses{Style.RESET_ALL}")
        return []

def get_mac_address() -> str:
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
        log(f"MAC Address: {mac}")
        print(f"{Fore.GREEN}MAC Address: {mac}{Style.RESET_ALL}")
        return mac
    except Exception as e:
        log(f"Error fetching MAC address: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching MAC address{Style.RESET_ALL}")
        return "Unknown"

def get_boot_time() -> str:
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        log(f"Boot Time: {boot_time}")
        print(f"{Fore.GREEN}Boot Time: {boot_time}{Style.RESET_ALL}")
        return boot_time
    except Exception as e:
        log(f"Error fetching boot time: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching boot time{Style.RESET_ALL}")
        return "Unknown"

def get_user_info() -> Dict[str, Any]:
    try:
        user_info = psutil.users()
        log(f"User Info: {user_info}")
        print(f"{Fore.GREEN}User Info: {user_info}{Style.RESET_ALL}")
        return user_info
    except Exception as e:
        log(f"Error fetching user info: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching user info{Style.RESET_ALL}")
        return {}

def get_disk_partitions() -> List[Dict[str, Any]]:
    try:
        partitions = psutil.disk_partitions()
        log(f"Disk Partitions: {partitions}")
        print(f"{Fore.GREEN}Disk Partitions: {json.dumps(partitions, indent=4)}{Style.RESET_ALL}")
        return partitions
    except Exception as e:
        log(f"Error fetching disk partitions: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching disk partitions{Style.RESET_ALL}")
        return []

def get_swap_memory() -> Dict[str, Any]:
    try:
        swap = psutil.swap_memory()
        log(f"Swap Memory: {swap}")
        print(f"{Fore.GREEN}Swap Memory: {swap}{Style.RESET_ALL}")
        return swap
    except Exception as e:
        log(f"Error fetching swap memory: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching swap memory{Style.RESET_ALL}")
        return {}

def get_network_io() -> Dict[str, Any]:
    try:
        net_io = psutil.net_io_counters()
        log(f"Network IO: {net_io}")
        print(f"{Fore.GREEN}Network IO: {net_io}{Style.RESET_ALL}")
        return net_io
    except Exception as e:
        log(f"Error fetching network IO: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching network IO{Style.RESET_ALL}")
        return {}

def get_disk_io() -> Dict[str, Any]:
    try:
        disk_io = psutil.disk_io_counters()
        log(f"Disk IO: {disk_io}")
        print(f"{Fore.GREEN}Disk IO: {disk_io}{Style.RESET_ALL}")
        return disk_io
    except Exception as e:
        log(f"Error fetching disk IO: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching disk IO{Style.RESET_ALL}")
        return {}

def get_open_files() -> List[str]:
    try:
        open_files = [f.path for f in psutil.Process().open_files()]
        log(f"Open Files: {open_files}")
        print(f"{Fore.GREEN}Open Files: {open_files}{Style.RESET_ALL}")
        return open_files
    except Exception as e:
        log(f"Error fetching open files: {e}", "ERROR")
        print(f"{Fore.RED}Error fetching open files{Style.RESET_ALL}")
        return []

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
    {Fore.CYAN}╔══════════════════════════════════════╗
    ║         {Fore.YELLOW}API CREATED TRACKER{Fore.CYAN}          ║
    ║             {Fore.YELLOW}BETA V1.0{Fore.CYAN}               ║
    ╚══════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def display_menu_category(category: str, options: Dict[str, str]) -> None:
    print(f"\n{Fore.BLUE}--- {category} ---{Style.RESET_ALL}")
    for key, value in options.items():
        print(f"{Fore.GREEN}{key}: {value}{Style.RESET_ALL}")

def display_how_to_use() -> None:
    print(f"\n{Fore.CYAN}=== How to Use This Script ==={Style.RESET_ALL}")
    print("This script provides various network and system analysis tools.")
    print("Each category in the menu offers different functionalities:")
    print("- Network Tools: Provides tools for network analysis, such as getting your public IP, scanning ports, and more.")
    print("- System Information: Provides information about your system, such as CPU usage, memory usage, and more.")
    print("- System Details: Provides detailed system information, such as system architecture, Python version, and more.")
    print("- Advanced Analysis: Provides advanced analysis tools, such as system vulnerability scanning and detailed network analysis.")
    print("- OSINT Web Scraper: Provides tools for scraping data from websites.")
    print("- Cyber Security Information: Provides information about cyber security best practices.")
    print("- Program Control: Provides options for rebooting the program or exiting.")
    print("- Firewall and Antivirus Status: Provides information about your firewall and antivirus status.")
    print("- Check Email Pwned Status: Checks if your email has been pwned in any data breaches.")
    print("To use a tool, enter the category number and then the option number.")
    print("For example, to get your public IP, enter '1' for Network Tools and then '1.1' for Public IP Information.")
    print("Enter 'q' to quit the program.")
    print(f"\n{Fore.CYAN}=== Ethical Use ==={Style.RESET_ALL}")
    print("This script is intended for ethical use only. Do not use it for illegal activities.")

def show_progress(description: str, total: int = 100) -> None:
    with tqdm(total=total, desc=description) as pbar:
        for _ in range(total):
            time.sleep(0.01)
            pbar.update(1)

def enhanced_port_scan(ip: str, start_port: int = 1, end_port: int = 1024) -> List[int]:
    open_ports = []
    with tqdm(total=end_port - start_port + 1, desc=f"Scanning ports for {ip}") as pbar:
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                pbar.update(1)
            except:
                pbar.update(1)
                continue
    return open_ports

def validate_input(prompt: str, validator: callable, error_msg: str) -> Any:
    while True:
        value = input(prompt)
        try:
            if validator(value):
                return value
        except ValueError:
                pass
        print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")

def handle_error(func: callable) -> callable:
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"{Fore.RED}Error in {func.__name__}: {str(e)}{Style.RESET_ALL}")
            log(f"Error in {func.__name__}: {str(e)}", "ERROR")
            return None
    return wrapper

@handle_error
def get_detailed_system_info() -> Dict[str, Any]:
    show_progress("Gathering system information...", total=100)
    
    info = {
        "system": platform.system(),
        "processor": platform.processor(),
        "architecture": platform.architecture(),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory": dict(psutil.virtual_memory()._asdict()),
        "disk": dict(psutil.disk_usage('/')._asdict()),
        "network": dict(psutil.net_io_counters()._asdict()),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "users": [dict(user._asdict()) for user in psutil.users()],
    }
    print(f"{Fore.GREEN}Detailed System Info: {json.dumps(info, indent=4)}{Style.RESET_ALL}")
    return info

def get_network_interfaces() -> List[Dict[str, Any]]:
    try:
        interfaces = []
        for name, addresses in psutil.net_if_addrs().items():
            interface_info = {
                "name": name,
                "addresses": [dict(addr._asdict()) for addr in addresses]
            }
            interfaces.append(interface_info)
        print(f"{Fore.GREEN}Network Interfaces: {json.dumps(interfaces, indent=4)}{Style.RESET_ALL}")
        return interfaces
    except Exception as e:
        log(f"Error getting network interfaces: {e}", "ERROR")
        print(f"{Fore.RED}Error getting network interfaces{Style.RESET_ALL}")
        return []

def phone_number_lookup(phone_number: str) -> Optional[Dict[str, str]]:
    try:
        parsed_number = phonenumbers.parse(phone_number, "US")
        if not phonenumbers.is_valid_number(parsed_number):
            log(f"Invalid phone number: {phone_number}", "WARNING")
            print(f"{Fore.RED}Invalid phone number: {phone_number}{Style.RESET_ALL}")
            return None

        number_data = {
            "phone_number": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country": geocoder.description_for_number(parsed_number, "en"),
            "carrier": carrier.name_for_number(parsed_number, "en"),
            "timezone": timezone.time_zones_for_number(parsed_number)
        }

        try:
            search_query = f"phone number {number_data['phone_number']}"
            search_results = search_phone_number_on_search_engines(search_query, number_data['phone_number'])
            number_data["osint_results"] = search_results
        except Exception as e:
            log(f"Error performing OSINT lookup: {e}", "ERROR")
            print(f"{Fore.RED}Error performing OSINT lookup{Style.RESET_ALL}")

        log(f"Phone number lookup results: {number_data}")
        print(f"{Fore.GREEN}Phone number lookup results: {json.dumps(number_data, indent=4)}{Style.RESET_ALL}")
        return number_data
    except phonenumbers.phonenumberutil.NumberParseException as e:
        log(f"Error parsing phone number: {e}", "ERROR")
        print(f"{Fore.RED}Error parsing phone number: {e}{Style.RESET_ALL}")
        return None
    except Exception as e:
        log(f"Error performing phone number lookup: {e}", "ERROR")
        print(f"{Fore.RED}Error performing phone number lookup{Style.RESET_ALL}")
        return None

def search_phone_number_on_search_engines(search_query: str, phone_number: str) -> List[str]:
    search_engines = {
        "Google": "https://www.google.com/search?q=",
        "Bing": "https://www.bing.com/search?q=",
        "DuckDuckGo": "https://duckduckgo.com/?q=",
        "Yahoo": "https://search.yahoo.com/search?p=",
        "Brave": "https://search.brave.com/search?q="
    }
    results = []
    for engine, base_url in search_engines.items():
        search_url = base_url + search_query.replace(" ", "+")
        try:
            response = requests.get(search_url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith("http") and phone_number in href:
                    results.append(f"{engine}: {href}")
        except Exception as e:
            log(f"Error searching {engine}: {e}", "ERROR")
            print(f"{Fore.RED}Error searching {engine}: {e}{Style.RESET_ALL}")
    return results

def brute_force_port_scan(ip: str, common_ports: List[int]) -> List[int]:
    open_ports = []
    with tqdm(total=len(common_ports), desc=f"Brute-forcing ports for {ip}") as pbar:
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                pbar.update(1)
            except:
                pbar.update(1)
                continue
    return open_ports

def generate_common_ports() -> List[int]:
    return list(range(1, 1025)) + [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443]

def social_media_osint_lookup(username: str) -> Dict[str, Any]:
    social_platforms = {
        "Twitter": {"url": f"https://twitter.com/{username}", "check": lambda soup: "Twitter" in soup.title.text},
        "Facebook": {"url": f"https://www.facebook.com/{username}", "check": lambda soup: "Facebook" in soup.title.text},
        "Instagram": {"url": f"https://www.instagram.com/{username}", "check": lambda soup: "Instagram" in soup.title.text},
        "LinkedIn": {"url": f"https://www.linkedin.com/in/{username}", "check": lambda soup: "LinkedIn" in soup.title.text},
        "GitHub": {"url": f"https://github.com/{username}", "check": lambda soup: "GitHub" in soup.title.text},
        "Reddit": {"url": f"https://www.reddit.com/user/{username}", "check": lambda soup: "Reddit" in soup.title.text},
        "YouTube": {"url": f"https://www.youtube.com/user/{username}", "check": lambda soup: "YouTube" in soup.title.text},
        "Pinterest": {"url": f"https://www.pinterest.com/{username}", "check": lambda soup: "Pinterest" in soup.title.text},
        "TikTok": {"url": f"https://www.tiktok.com/@{username}", "check": lambda soup: "TikTok" in soup.title.text},
        "Tumblr": {"url": f"https://{username}.tumblr.com", "check": lambda soup: "Tumblr" in soup.title.text},
        "Snapchat": {"url": f"https://www.snapchat.com/add/{username}", "check": lambda soup: "Snapchat" in soup.title.text},
        "Vimeo": {"url": f"https://vimeo.com/{username}", "check": lambda soup: "Vimeo" in soup.title.text},
        "Twitch": {"url": f"https://www.twitch.tv/{username}", "check": lambda soup: "Twitch" in soup.title.text},
        "Discord": {"url": f"https://discord.com/users/{username}", "check": lambda soup: "Discord" in soup.title.text},
        "Telegram": {"url": f"https://t.me/{username}", "check": lambda soup: "Telegram" in soup.title.text},
        "Medium": {"url": f"https://medium.com/@{username}", "check": lambda soup: "Medium" in soup.title.text},
        "Patreon": {"url": f"https://www.patreon.com/{username}", "check": lambda soup: "Patreon" in soup.title.text},
        "DeviantArt": {"url": f"https://www.deviantart.com/{username}", "check": lambda soup: "DeviantArt" in soup.title.text},
        "SoundCloud": {"url": f"https://soundcloud.com/{username}", "check": lambda soup: "SoundCloud" in soup.title.text},
        "Spotify": {"url": f"https://open.spotify.com/user/{username}", "check": lambda soup: "Spotify" in soup.title.text},
        "Steam": {"url": f"https://steamcommunity.com/id/{username}", "check": lambda soup: "Steam" in soup.title.text},
        "Xbox Live": {"url": f"https://account.xbox.com/en-us/Profile?gamerTag={username}", "check": lambda soup: "Xbox" in soup.title.text},
        "PlayStation Network": {"url": f"https://psnprofiles.com/{username}", "check": lambda soup: "PSN" in soup.title.text},
        "About.me": {"url": f"https://about.me/{username}", "check": lambda soup: "About.me" in soup.title.text},
        "Gravatar": {"url": f"https://en.gravatar.com/{username}", "check": lambda soup: "Gravatar" in soup.title.text},
        "Crunchbase": {"url": f"https://www.crunchbase.com/{username}", "check": lambda soup: "Crunchbase" in soup.title.text},
        "Goodreads": {"url": f"https://www.goodreads.com/user/show/{username}", "check": lambda soup: "Goodreads" in soup.title.text},
        "Last.fm": {"url": f"https://www.last.fm/user/{username}", "check": lambda soup: "Last.fm" in soup.title.text}
    }
    results = {}
    for platform, details in social_platforms.items():
        url = details["url"]
        try:
            headers = {'User-Agent': UserAgent().random}
            proxies = fetch_proxies()
            proxy = random.choice(proxies) if proxies else None
            if proxy:
                response = requests.get(url, headers=headers, proxies={"http": proxy, "https": proxy}, timeout=10)
            else:
                response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            if details["check"](soup):
                results[platform] = {"status": "ACTIVE", "url": url}
            else:
                results[platform] = {"status": "INACTIVE", "url": url}
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                results[platform] = {"status": "NOT FOUND", "url": url}
            else:
                results[platform] = {"status": f"ERROR: {e}", "url": url}
            logging.error(f"HTTP error on {platform}: {e}")
            print(f"{Fore.RED}HTTP error on {platform}: {e}{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error on {platform}: {e}")
            print(f"{Fore.RED}Request error on {platform}: {e}{Style.RESET_ALL}")
            results[platform] = {"status": f"ERROR: {e}", "url": url}
        except Exception as e:
            logging.error(f"Unexpected error on {platform}: {e}")
            print(f"{Fore.RED}Unexpected error on {platform}: {e}{Style.RESET_ALL}")
            results[platform] = {"status": f"ERROR: {e}", "url": url}
        time.sleep(1)
    nicknames = generate_nickname_variations(username)
    results["nickname_variations"] = nicknames
    print(f"{Fore.GREEN}Social Media Lookup Results: {json.dumps(results, indent=4)}{Style.RESET_ALL}")
    return results

def generate_nickname_variations(username: str) -> List[str]:
    variations = [username, username.lower(), username.upper(), username.capitalize()]
    variations.extend([f"{username}{i}" for i in range(10)])
    variations.extend([username.replace("", "_"), username.replace("", ".")])
    prefixes = ["the", "official", "real"]
    suffixes = ["fan", "official", "hq"]
    variations.extend([f"{prefix}{username}" for prefix in prefixes])
    variations.extend([f"{username}{suffix}" for suffix in suffixes])
    return list(set(variations))

def get_detailed_network_analysis() -> None:
    try:
        print(f"{Fore.CYAN}Performing detailed network analysis...{Style.RESET_ALL}")
        interfaces = get_network_interfaces()
        if interfaces:
            print(f"{Fore.GREEN}Network Interfaces: {json.dumps(interfaces, indent=4)}{Style.RESET_ALL}")

        public_ip = get_public_ip()
        if public_ip:
            print(f"{Fore.GREEN}Public IP: {public_ip}{Style.RESET_ALL}")
            location_data = get_location(public_ip)
            if location_data:
                print(f"{Fore.GREEN}Location Data: {json.dumps(location_data, indent=4)}{Style.RESET_ALL}")

        domain = input(f"{Fore.YELLOW}Enter domain for DNS lookup: {Style.RESET_ALL}")
        dns_lookup(domain)

        ip = input(f"{Fore.YELLOW}Enter IP for reverse DNS lookup: {Style.RESET_ALL}")
        if validate_ip(ip):
            reverse_dns(ip)
        else:
            print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")

        ip = input(f"{Fore.YELLOW}Enter IP for WHOIS lookup: {Style.RESET_ALL}")
        if validate_ip(ip):
            whois_lookup(ip)
        else:
            print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")

        ip = input(f"{Fore.YELLOW}Enter IP for traceroute: {Style.RESET_ALL}")
        if validate_ip(ip):
            run_traceroute(ip)
        else:
            print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")

        ip = input(f"{Fore.YELLOW}Enter IP for port scanning: {Style.RESET_ALL}")
        if validate_ip(ip):
            port_scan(ip)
        else:
            print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")

        ip_or_url = input(f"{Fore.YELLOW}Enter IP or URL for IPinfo.io scan: {Style.RESET_ALL}")
        if validate_ip(ip_or_url) or validate_url(ip_or_url):
            scan_with_ip_api(ip_or_url)
        else:
            print(f"{Fore.RED}Invalid IP address or URL.{Style.RESET_ALL}")

        print(f"{Fore.CYAN}Detailed network analysis completed.{Style.RESET_ALL}")
    except Exception as e:
        log(f"Error performing detailed network analysis: {e}", "ERROR")
        print(f"{Fore.RED}Error performing detailed network analysis: {e}{Style.RESET_ALL}")

def check_email_pwned(email: str) -> None:
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {'User-Agent': 'Advanced-IP-Tracker'}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(f"{Fore.GREEN}Email {email} has been pwned in the following breaches:{Style.RESET_ALL}")
            for breach in data:
                print(f"{Fore.YELLOW}- {breach['Name']}{Style.RESET_ALL}")
        elif response.status_code == 404:
            print(f"{Fore.GREEN}Email {email} has not been pwned in any known data breaches.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Error checking email {email}: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        log(f"Error checking email pwned status: {e}", "ERROR")
        print(f"{Fore.RED}Error checking email pwned status: {e}{Style.RESET_ALL}")

def data_breach_lookup(search_term: str) -> List[Dict[str, Any]]:
    results = []
    try:
        headers = {'User-Agent': UserAgent().random}
        if "@gmail.com" in search_term:
            url = f"https://leak-lookup.com/api/search?type=email&value={search_term}"
        else:
            url = f"https://leak-lookup.com/api/search?type=email&value={search_term}"

        proxies = fetch_proxies()
        proxy = random.choice(proxies) if proxies else None
        if proxy:
            response = requests.get(url, headers=headers, proxies={"http": proxy, "https": proxy}, timeout=10)
        else:
            response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            results.extend(data)
        else:
            log(f"Unexpected data format: {data}", "WARNING")
            print(f"{Fore.YELLOW}Unexpected data format: {data}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        log(f"Error during data breach lookup: {e}", "ERROR")
        print(f"{Fore.RED}Error during data breach lookup: {e}{Style.RESET_ALL}")
    except Exception as e:
        log(f"Unexpected error during data breach lookup: {e}", "ERROR")
        print(f"{Fore.RED}Unexpected error during data breach lookup: {e}{Style.RESET_ALL}")
    return results

def analyze_text_sentiment(text: str) -> Dict[str, float]:
    try:
        sid = SentimentIntensityAnalyzer()
        scores = sid.polarity_scores(text)
        log(f"Sentiment analysis scores: {scores}")
        print(f"{Fore.GREEN}Sentiment analysis scores: {scores}{Style.RESET_ALL}")
        return scores
    except Exception as e:
        log(f"Error analyzing text sentiment: {e}", "ERROR")
        print(f"{Fore.RED}Error analyzing text sentiment: {e}{Style.RESET_ALL}")
        return {}

async def enhanced_osint_lookup(name: str) -> Dict[str, Any]:
    results = {}

    try:
        search_query = f'"{name}"'
        search_results = search_phone_number_on_search_engines(search_query, "")
        results['search_results'] = search_results

        social_results = social_media_osint_lookup(name)
        results['social_media'] = {}
        for platform, data in social_results.items():
            if platform != "nickname_variations":
                is_valid = verify_link(data.get("url", ""))
                results['social_media'][platform] = {
                    "status": data.get("status"),
                    "url": data.get("url"),
                    "account_exists": is_valid
                }
            else:
                results['social_media']["nickname_variations"] = data

        discord_id = discord_id_lookup(name)
        results['discord_id'] = discord_id

        email = None
        email_list = []
        for result in search_results:
            email_match = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", result)
            if email_match:
                email_list.extend(email_match)
        results['email_addresses'] = list(set(email_list))

        phone_number = None
        phone_number_list = []
        for result in search_results:
            phone_match = re.findall(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", result)
            if phone_match:
                phone_number_list.extend(phone_match)
        results['phone_numbers'] = list(set(phone_number_list))

        if results['email_addresses']:
            all_data_breaches = []
            for email in results['email_addresses']:
                data_breach_results = data_breach_lookup(email)
                all_data_breaches.extend(data_breach_results)
            results['data_breaches'] = all_data_breaches
        else:
            results['data_breaches'] = "No email found to perform data breach lookup"

    except Exception as e:
        log(f"Error performing enhanced OSINT lookup: {e}", "ERROR")
        print(f"{Fore.RED}Error performing enhanced OSINT lookup: {e}{Style.RESET_ALL}")
        results['error'] = str(e)

    print(f"{Fore.GREEN}Enhanced OSINT Lookup Results: {json.dumps(results, indent=4)}{Style.RESET_ALL}")
    return results

def verify_link(url: str) -> bool:
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def discord_id_lookup(username: str) -> Optional[str]:
    try:
        return f"Discord ID: {uuid.uuid4()}"
    except Exception as e:
        log(f"Error performing Discord ID lookup: {e}", "ERROR")
        print(f"{Fore.RED}Error performing Discord ID lookup: {e}{Style.RESET_ALL}")
        return None

async def menu() -> None:
    while True:
        clear_screen()
        print_banner()
        
        categories = {
            "1": ("Network Tools", {
                "0": "Public IP Information",
                "1": "Advanced Port Scanner",
                "2": "Network Analysis",
                "3": "Get Network Interfaces",
                "4": "DNS Lookup",
                "5": "Reverse DNS Lookup",
                "6": "IP Lookup",
                "7": "Brute-Force Port Scan"
            }),
            "2": ("System Information", {
                "0": "Detailed System Info",
                "1": "Performance Monitor",
                "2": "Resource Usage",
            }),
            "3": ("System Details", {
                "0": "Get System Architecture",
                "1": "Get Python Version",
                "2": "Get Hostname",
            }),
            "4": ("Advanced Analysis", {
                "0": "System Vulnerability Scan",
                "1": "Detailed Network Analysis",
            }),
            "5": ("OSINT Web Scraper", {
                "0": "Scrape Website Data",
            }),
            "6": ("Cyber Security Information", {
                "0": "Cyber Security Best Practices",
                "1": "Social Media Lookup",
            }),
            "7": ("Program Control", {
                "0": "Reboot Program",
                "1": "Exit",
            }),
            "8": ("Firewall and Antivirus Status", {
                "0": "Get Firewall Status",
                "1": "Get Antivirus Status",
            }),
            "9": ("Check Email Pwned Status", {
                "0": "Check Email Pwned Status",
            }),
            "10": ("How to Use", {
                "0": "Information on how to use this script",
            }),
            "11": ("Phone Number Lookup", {
                "0": "Perform phone number lookup",
            }),
            "12": ("Data Breach Lookup", {
                "0": "Lookup data breaches by Email",
            }),
            "13": ("Text Sentiment Analysis", {
                "0": "Analyze sentiment of a text",
            }),
            "14": ("Website Content Analysis", {
                "0": "Analyze content of a website",
            }),
            "15": ("Enhanced OSINT Lookup", {
                "0": "Perform enhanced OSINT lookup by name",
            }),
            "00": ("Go Back", {
                "0": "Return to the main menu",
            }),
        }

        for key, (category, options) in categories.items():
            display_menu_category(f"{key}. {category}", options)

        choice = validate_input(
            f"{Fore.YELLOW}Enter your choice (or press Esc to go back, or 'q' to quit): {Style.RESET_ALL}",
            lambda x: x.lower() == 'q' or x in categories,
            "Invalid choice. Please try again."
        )

        if choice.lower() == 'q':
            print(f"{Fore.YELLOW}Goodbye!{Style.RESET_ALL}")
            break

        if choice == "10":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                display_how_to_use()
                input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            continue
        
        if choice == "11":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                phone_number = input(f"{Fore.YELLOW}Enter phone number to lookup (e.g., +14155552671): {Style.RESET_ALL}")
                number_data = phone_number_lookup(phone_number)
                if number_data:
                    print(f"{Fore.GREEN}Phone Number Information: {json.dumps(number_data, indent=4)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Could not retrieve phone number information.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "6":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-1): {Style.RESET_ALL}")
            if sub_choice == "1":
                username = input(f"{Fore.YELLOW}Enter username to lookup on social media: {Style.RESET_ALL}")
                social_media_osint_lookup(username)
            elif sub_choice == "0":
                print(f"{Fore.CYAN}Cyber Security Best Practices:{Style.RESET_ALL}")
                print("Wireshark: A tool for checking network data and traffic.")
                print("Terminal Commands: Use (cls) to clear the terminal screen.")
                print("Terminal Commands: Use (cd <directory>) to go to a folder.")
                print("Learn Python for AI, Malware analysis, Virus detection, and more.")
                print("To run a Python program: Type 'python <filename>.py' in the terminal.")
                print("Top Free Antivirus: Bitdefender, Malwarebytes, Windows antivirus.")
                print("Best Free VPNs: Urban VPN, ProtonVPN, Windscribe.")
                print("Recommended Browsers: Brave, Firefox, Chromium, Tor for privacy.")
                print("Top Linux OS: Arch Linux, Linux Mint (good for beginners).")
                print("Use a Password Manager: Keep your passwords safe and strong.")
                print("Enable Two-Factor Authentication (2FA): Adds extra security to your accounts.")
                print("Keep Software Updated: Updates fix bugs and security problems.")
                print("Be cautious with Phishing: Always check links before clicking.")
                print("Regularly Back Up Your Data: Save copies of important files in case something goes wrong.")
                print("Use Encryption: Protect your files so no one can read them without a key.")
                print("Monitor Your Network: Watch for unusual activity with tools like Wireshark.")
                print("Understand Firewalls: Firewalls stop harmful traffic from entering your system.")
                print("Secure Your Wi-Fi: Use WPA3 and a strong password to protect your Wi-Fi.")
                print("Familiarize Yourself with the CIA Triad: Confidentiality, Integrity, Availability.")
                print("Be aware of Social Engineering: Don’t give out personal info to strangers online.")
                print("Doxxing and Doxxbin: Doxxing is publishing private info to harm someone. Sites like Doxxbin are illegal and dangerous.")
                print("Learn about Cyberbullying: Report harmful online behavior and stay kind.")
                print("Keep Personal Info Private: Don’t share your address or phone number online.")
                print("Be Careful with Public Wi-Fi: Public Wi-Fi can be unsafe for sensitive activities.")
                print("Understand VPNs and Proxies: VPNs hide your IP address. Proxies act as a middleman to protect your privacy.")
                print("Don’t Download Files from Unknown Sources: Always download files from trusted sites.")
                print("Spot Fake Websites: Check the URL to make sure it’s a real site.")
                print("Know Your Digital Footprint: Everything you do online can be tracked.")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "1":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-7): {Style.RESET_ALL}")
            if sub_choice == "0":
                await get_public_ip()
            elif sub_choice == "1":
                ip = input(f"{Fore.YELLOW}Enter IP to scan: {Style.RESET_ALL}")
                if validate_ip(ip):
                    start_port = int(validate_input(f"{Fore.YELLOW}Enter start port: {Style.RESET_ALL}", lambda x: x.isdigit(), "Invalid port number"))
                    end_port = int(validate_input(f"{Fore.YELLOW}Enter end port: {Style.RESET_ALL}", lambda x: x.isdigit() and int(x) > start_port, "Invalid port number"))
                    open_ports = await enhanced_port_scan(ip, start_port, end_port)
                    print(f"{Fore.GREEN}Open Ports: {open_ports}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")
            elif sub_choice == "2":
                get_detailed_network_analysis()
            elif sub_choice == "3":
                get_network_interfaces()
            elif sub_choice == "4":
                domain = input(f"{Fore.YELLOW}Enter domain for DNS lookup: {Style.RESET_ALL}")
                await dns_lookup(domain)
            elif sub_choice == "5":
                ip = input(f"{Fore.YELLOW}Enter IP for reverse DNS lookup: {Style.RESET_ALL}")
                if validate_ip(ip):
                    await reverse_dns(ip)
                else:
                    print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")
            elif sub_choice == "6":
                ip = input(f"{Fore.YELLOW}Enter IP for WHOIS lookup: {Style.RESET_ALL}")
                if validate_ip(ip):
                    await whois_lookup(ip)
                else:
                    print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")
            elif sub_choice == "7":
                ip = input(f"{Fore.YELLOW}Enter IP for brute-force port scan: {Style.RESET_ALL}")
                if validate_ip(ip):
                    common_ports = generate_common_ports()
                    open_ports = brute_force_port_scan(ip, common_ports)
                    print(f"{Fore.GREEN}Open Ports: {open_ports}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Invalid IP address.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "2":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-2): {Style.RESET_ALL}")
            if sub_choice == "0":
                get_detailed_system_info()
            elif sub_choice == "1":
                print(f"{Fore.CYAN}Performance Monitor:{Style.RESET_ALL}")
                print(f"{Fore.GREEN}CPU Usage: {get_cpu_usage()}%{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Memory Usage: {get_memory_usage()}%{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Disk Usage: {get_disk_usage()}%{Style.RESET_ALL}")
            elif sub_choice == "2":
                print(f"{Fore.CYAN}Resource Usage:{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Network Info: {json.dumps(get_network_info(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Screen Resolution: {get_screen_resolution()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Running Processes: {get_running_processes()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Installed Packages: {get_installed_packages()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}System Uptime: {get_system_uptime()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Battery Status: {json.dumps(get_battery_status(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Temperature Sensors: {json.dumps(get_temperature_sensors(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Fan Speeds: {json.dumps(get_fan_speeds(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}System Architecture: {get_system_architecture()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Python Version: {get_python_version()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Hostname: {get_hostname()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}IP Addresses: {get_ip_addresses()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}MAC Address: {get_mac_address()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Boot Time: {get_boot_time()}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}User Info: {json.dumps(get_user_info(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Disk Partitions: {json.dumps(get_disk_partitions(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Swap Memory: {json.dumps(get_swap_memory(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Network IO: {json.dumps(get_network_io(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Disk IO: {json.dumps(get_disk_io(), indent=4)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Open Files: {get_open_files()}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "3":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-2): {Style.RESET_ALL}")
            if sub_choice == "0":
                print(f"{Fore.GREEN}System Architecture: {get_system_architecture()}{Style.RESET_ALL}")
            elif sub_choice == "1":
                print(f"{Fore.GREEN}Python Version: {get_python_version()}{Style.RESET_ALL}")
            elif sub_choice == "2":
                print(f"{Fore.GREEN}Hostname: {get_hostname()}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "4":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-1): {Style.RESET_ALL}")
            if sub_choice == "0":
                print(f"{Fore.CYAN}System Vulnerability Scan:{Style.RESET_ALL}")
                print("This feature is under development.")
            elif sub_choice == "1":
                get_detailed_network_analysis()
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "5":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                urls = input(f"{Fore.YELLOW}Enter URLs to scrape (comma-separated): {Style.RESET_ALL}").split(",")
                total_pages = int(validate_input(f"{Fore.YELLOW}Enter total pages to scrape: {Style.RESET_ALL}", lambda x: x.isdigit(), "Invalid number"))
                data = scrape_multiple_urls(urls, total_pages)
                save_encrypted_data(data)
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "7":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-1): {Style.RESET_ALL}")
            if sub_choice == "0":
                reboot_program()
            elif sub_choice == "1":
                print(f"{Fore.YELLOW}bye{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "8":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0-1): {Style.RESET_ALL}")
            if sub_choice == "0":
                print(f"{Fore.CYAN}Firewall Status:{Style.RESET_ALL}")
                print("This feature is under development.")
            elif sub_choice == "1":
                print(f"{Fore.CYAN}Antivirus Status:{Style.RESET_ALL}")
                print("This feature is under development.")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "9":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                email = input(f"{Fore.YELLOW}Enter email to check pwned status: {Style.RESET_ALL}")
                check_email_pwned(email)
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "12":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                search_term = input(f"{Fore.YELLOW}Enter email to lookup data breaches: {Style.RESET_ALL}")
                results = data_breach_lookup(search_term)
                if results:
                    print(f"{Fore.GREEN}Data Breach Lookup Results: {json.dumps(results, indent=4)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}No data breaches found for {search_term}.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "13":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                text = input(f"{Fore.YELLOW}Enter text to analyze sentiment: {Style.RESET_ALL}")
                analyze_text_sentiment(text)
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "14":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                url = input(f"{Fore.YELLOW}Enter URL to analyze content: {Style.RESET_ALL}")
                html = fetch_html(url)
                if html:
                    links, text_content = extract_data_from_html(html, url)
                    print(f"{Fore.GREEN}Extracted Links: {json.dumps(links, indent=4)}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}Extracted Content: {json.dumps(text_content, indent=4)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Failed to fetch HTML content from {url}.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

        if choice == "15":
            sub_choice = input(f"{Fore.YELLOW}Choose an option (0): {Style.RESET_ALL}")
            if sub_choice == "0":
                name = input(f"{Fore.YELLOW}Enter name to perform enhanced OSINT lookup: {Style.RESET_ALL}")
                enhanced_osint_lookup(name)
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Press Enter to return to the main menu...{Style.RESET_ALL}")
            continue

async def main():
    setup_database()
    try:
        await menu()
    except Exception as e:
        log(f"An error occurred: {e}", "ERROR")
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")
    finally:
        print("Program finished.")

if __name__ == "__main__":
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except Exception as e:
        print(f"An error occurred during startup: {e}")
        log(f"An error occurred during startup: {e}", "ERROR")
