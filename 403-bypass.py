import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init

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

def test_url_payloads(base_url, payloads):
    """Test each URL payload."""
    if not payloads:
        print(f"{Fore.RED}No URL payloads to test.")
        return
    
    print(f"\n{Fore.CYAN}Testing URL payloads on: {Fore.YELLOW}{base_url}")
    for payload in payloads:
        test_url = f"{base_url.rstrip('/')}/{payload.lstrip('/')}"
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            status_code = response.status_code
            if status_code == 200:
                color = Fore.GREEN
            elif status_code == 403:
                color = Fore.RED
            else:
                color = Fore.YELLOW

            print(f"{color}URL: {test_url} - Status Code: {status_code}")
            if status_code == 200:
                print(f"{Fore.GREEN}[+] Bypass successful with URL: {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error with URL {test_url}: {e}")

def test_header_payloads(url, headers):
    """Test each header against the target URL."""
    if not headers:
        print(f"{Fore.RED}No headers to test.")
        return
    
    print(f"\n{Fore.CYAN}Testing headers on: {Fore.YELLOW}{url}")
    for header, value in headers.items():
        try:
            response = requests.get(url, headers={header: value}, timeout=5, verify=False)
            status_code = response.status_code
            if status_code == 200:
                color = Fore.GREEN
            elif status_code == 403:
                color = Fore.RED
            else:
                color = Fore.YELLOW

            print(f"{color}Header: {header} - Status Code: {status_code}")
            if status_code == 200:
                print(f"{Fore.GREEN}[+] Bypass successful with {header}: {value}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error with header {header}: {e}")

def main():
    # Print the banner
    print_banner()

    # Ask for inputs with colored prompts
    url = input(f"{Fore.CYAN}Enter the target website URL: {Fore.YELLOW}").strip()
    bypass_type = input(f"{Fore.CYAN}Select bypass type (1 for URL Bypass, 2 for Header Bypass): {Fore.YELLOW}").strip()

    if bypass_type == "1":
        payload_file = input(f"{Fore.CYAN}Enter the path to the URL payloads list file: {Fore.YELLOW}").strip()
        payloads = load_payloads(payload_file)
        if payloads:
            test_url_payloads(url, payloads)
    elif bypass_type == "2":
        headers_file = input(f"{Fore.CYAN}Enter the path to the headers list file: {Fore.YELLOW}").strip()
        headers = {}
        header_lines = load_payloads(headers_file)
        if header_lines:
            for line in header_lines:
                if ': ' in line:
                    header, value = line.split(': ', 1)
                    headers[header] = value
            test_header_payloads(url, headers)
    else:
        print(f"{Fore.RED}Invalid option. Please select 1 or 2.")

if __name__ == "__main__":
    main()
