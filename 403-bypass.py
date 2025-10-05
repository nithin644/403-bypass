import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init
import os
import argparse
import sys
import csv
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import concurrent.futures
import threading

# Initialize colorama
init(autoreset=True)

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def print_banner():
    """Print the custom ASCII banner."""
    banner = """
 a88888b.          dP                             .88888.  dP                           dP   
d8'   `88          88                            d8'   `88 88                           88   
88        dP    dP 88d888b. .d8888b. 88d888b.    88        88d888b. .d8888b. .d8888b. d8888P 
88        88    88 88'  `88 88ooood8 88'  `88    88   YP88 88'  `88 88'  `88 Y8ooooo.   88   
Y8.   .88 88.  .88 88.  .88 88.  ... 88          Y8.   .88 88    88 88.  .88       88   88   
 Y88888P' `8888P88 88Y8888' `88888P' dP           `88888'  dP    dP `88888P' `88888P'   dP   
               .88                                                                           
           d8888P                                                                            
    """
    print(Fore.GREEN + banner)
    # Author line and professional accent
    print(Fore.MAGENTA + "Author <3 Nithin".center(72))
    print(Fore.BLUE + "=" * 72)


def print_info(msg):
    print(Fore.CYAN + "[i] " + Style.RESET_ALL + msg)


def print_success(msg):
    print(Fore.GREEN + "[+] " + Style.RESET_ALL + msg)


def print_warn(msg):
    print(Fore.YELLOW + "[!] " + Style.RESET_ALL + msg)


def print_error(msg):
    print(Fore.RED + "[-] " + Style.RESET_ALL + msg)


def print_section(title):
    print('\n' + Fore.MAGENTA + '=' * 8 + ' ' + title + ' ' + '=' * 8)


def get_status_color(status_code):
    """Return a Fore color for a given HTTP status code."""
    try:
        code = int(status_code)
    except Exception:
        return Fore.WHITE
    if 200 <= code < 300:
        return Fore.GREEN
    if 300 <= code < 400:
        return Fore.CYAN
    if 400 <= code < 500:
        # show 403 in red, other 4xx in yellow
        if code == 403:
            return Fore.RED
        return Fore.YELLOW
    if 500 <= code < 600:
        return Fore.MAGENTA
    return Fore.WHITE

def load_payloads(file_path):
    """Load payloads from a file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}File not found: {file_path}")
        return None
    except Exception as e:
        print(f"{Fore.RED}Error loading payloads: {e}")
        return None


def create_session(retries=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504)):
    """Create a requests.Session with retry strategy."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def normalize_url(url):
    """Ensure URL has a scheme; default to http if missing."""
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'http://' + url
    return url


def build_test_url(base_url, payload):
    """Build test URL handling query-only payloads and absolute payloads."""
    if payload.startswith('http://') or payload.startswith('https://'):
        return payload
    if payload.startswith('?') or payload.startswith('#'):
        return base_url.rstrip('/') + payload
    return f"{base_url.rstrip('/')}/{payload.lstrip('/')}"


def parse_header_lines(header_lines):
    """Parse header lines into a list of (header, value) tuples preserving duplicates."""
    headers = []
    for line in header_lines:
        if not line or line.strip().startswith('#'):
            continue
        if ':' in line:
            name, val = line.split(':', 1)
            headers.append((name.strip(), val.strip()))
    return headers

def test_url_payloads(base_url, payloads, session, timeout, counters, bypasses, verify=False, threads=1):
    """Test each URL payload. Thread-safe. Updates counters and bypasses list."""
    if not payloads:
        print(f"{Fore.RED}No URL payloads to test.")
        return

    print_section(f"URL Payloads -> {base_url}")
    total = len(payloads)
    lock = threading.Lock()

    def worker(item):
        idx, payload = item
        test_url = build_test_url(base_url, payload)
        try:
            response = session.get(test_url, timeout=timeout, verify=verify)
            status_code = response.status_code
            status_label = f"{status_code}"
            color = get_status_color(status_code)
            line = f"[{idx}/{total}] {test_url} -> {status_label}"
            print(color + line + Style.RESET_ALL)
            if status_code == 200:
                print_success(f"Bypass successful: {test_url}")
                with lock:
                    bypasses.append({'type': 'url', 'target': base_url, 'payload': payload, 'result_url': test_url, 'status': status_code})
                    counters['bypasses'] += 1
        except requests.exceptions.ReadTimeout:
            print_error(f"[{idx}/{total}] Read timeout for URL {test_url}")
            with lock:
                counters['errors'] += 1
        except requests.exceptions.RequestException as e:
            print_error(f"[{idx}/{total}] Error with URL {test_url}: {e}")
            with lock:
                counters['errors'] += 1
        finally:
            with lock:
                counters['total_tests'] += 1

    items = list(enumerate(payloads, start=1))
    if threads and threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(worker, items))
    else:
        for item in items:
            worker(item)

def test_header_payloads(url, header_tuples, session, timeout, counters, bypasses, verify=False, threads=1):
    """Test each header (tuple list) against the target URL. Thread-safe."""
    if not header_tuples:
        print(f"{Fore.RED}No headers to test.")
        return

    print_section(f"Header Tests -> {url}")
    total = len(header_tuples)
    lock = threading.Lock()

    def worker(item):
        idx, (header, value) = item
        try:
            response = session.get(url, headers={header: value}, timeout=timeout, verify=verify)
            status_code = response.status_code
            status_label = f"{status_code}"
            color = get_status_color(status_code)
            line = f"[{idx}/{total}] {header}: {value} -> {status_label}"
            print(color + line + Style.RESET_ALL)
            if status_code == 200:
                print_success(f"Bypass successful: {header}: {value} on {url}")
                with lock:
                    bypasses.append({'type': 'header', 'target': url, 'header': header, 'value': value, 'status': status_code})
                    counters['bypasses'] += 1
        except requests.exceptions.ReadTimeout:
            print_error(f"[{idx}/{total}] Read timeout for header {header} on {url}")
            with lock:
                counters['errors'] += 1
        except requests.exceptions.RequestException as e:
            print_error(f"[{idx}/{total}] Error with header {header}: {e}")
            with lock:
                counters['errors'] += 1
        finally:
            with lock:
                counters['total_tests'] += 1

    items = list(enumerate(header_tuples, start=1))
    if threads and threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(worker, items))
    else:
        for item in items:
            worker(item)

def main():
    # Print the banner
    print_banner()
    # CLI arguments
    parser = argparse.ArgumentParser(description='403 bypass testing tool')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', '--url', help='Single target URL to test')
    group.add_argument('-l', '--list', help='File containing list of target URLs (one per line)')
    parser.add_argument('-p', '--payloads', help="Path to payloads file to use for URL tests (if omitted, default '403_url_payloads.txt' is used)")
    parser.add_argument('--headers', help="Path to header payloads file (if omitted, default '403_header_payloads.txt' is used)")
    parser.add_argument('-o', '--output', help='Path to save discovered bypasses (CSV)')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Number of threads to use for testing (default 1)')
    parser.add_argument('--timeout', type=float, default=7.0, help='Request timeout in seconds (default 7)')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification (default: verify certificates)')
    args = parser.parse_args()

    script_dir = os.path.dirname(__file__)

    # Determine payload files (use defaults if not provided)
    url_payload_file = args.payloads if args.payloads else os.path.join(script_dir, '403_url_payloads.txt')
    header_payload_file = args.headers if args.headers else os.path.join(script_dir, '403_header_payloads.txt')

    # Prepare counters and results
    counters = {'total_tests': 0, 'bypasses': 0, 'errors': 0}
    bypasses = []

    # Create session with retries
    session = create_session()

    # Determine targets
    targets = []
    if args.url:
        targets = [args.url]
    elif args.list:
        lines = load_payloads(args.list)
        if lines:
            targets = [line for line in lines if line and not line.startswith('#')]
    else:
        # Interactive fallback
        url = input(f"{Fore.CYAN}Enter the target website URL: {Fore.YELLOW}").strip()
        if not url:
            print(f"{Fore.RED}No target URL provided. Exiting.")
            sys.exit(1)
        targets = [url]

    # Load payloads and headers
    url_payloads = load_payloads(url_payload_file)
    header_lines = load_payloads(header_payload_file)
    header_tuples = parse_header_lines(header_lines) if header_lines else None

    verify = not args.no_verify

    # Run tests for each target
    for target in targets:
        target = normalize_url(target)
        if url_payloads:
            test_url_payloads(target, url_payloads, session, timeout=args.timeout, counters=counters, bypasses=bypasses, verify=verify, threads=args.threads)
        if header_tuples:
            test_header_payloads(target, header_tuples, session, timeout=args.timeout, counters=counters, bypasses=bypasses, verify=verify, threads=args.threads)

    # Summary
    print(f"\n{Fore.CYAN}Test summary:{Fore.YELLOW} Total tests={counters['total_tests']}, Bypasses={counters['bypasses']}, Errors={counters['errors']}")

    # Optionally save bypasses
    if args.output and bypasses:
        out_path = args.output
        try:
            with open(out_path, 'w', newline='') as csvfile:
                fieldnames = set()
                for item in bypasses:
                    fieldnames.update(item.keys())
                fieldnames = list(fieldnames)
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for item in bypasses:
                    writer.writerow(item)
            print(f"{Fore.GREEN}Saved {len(bypasses)} bypasses to {out_path}")
        except Exception as e:
            print(f"{Fore.RED}Failed to save bypasses: {e}")
    elif bypasses:
        # Ask interactively to save
        save_input = input(f"{Fore.CYAN}Save bypasses to a file? (y/N): {Fore.YELLOW}").strip().lower()
        if save_input in ('y', 'yes'):
            out_path = input(f"{Fore.CYAN}Enter output CSV path: {Fore.YELLOW}").strip()
            try:
                with open(out_path, 'w', newline='') as csvfile:
                    fieldnames = set()
                    for item in bypasses:
                        fieldnames.update(item.keys())
                    fieldnames = list(fieldnames)
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for item in bypasses:
                        writer.writerow(item)
                print(f"{Fore.GREEN}Saved {len(bypasses)} bypasses to {out_path}")
            except Exception as e:
                print(f"{Fore.RED}Failed to save bypasses: {e}")
    # end of main

if __name__ == "__main__":
    main()
