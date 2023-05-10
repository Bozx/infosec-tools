# twitter.com/slymn_clkrsln
# This tool checks bunch of given URLs if there is a Basic HTTP Authentication is required, with multi threaded way. 
import requests
import concurrent.futures

requests.packages.urllib3.disable_warnings()

def check_http_auth(url):
    try:
        r = requests.get(url, auth=('username', 'password'), verify=False, timeout=5)
        if r.status_code == 401:
            print(f'[+] HTTP Basic Auth detected at {url}')
            with open('http-auths.txt', 'a') as f:
                f.write(url + '\n')
    except Exception as e:
        print(f'[!] Error checking {url}: {e}')

def read_urls_from_file(file_path):
    with open(file_path, 'r') as f:
        urls = f.read().splitlines()
    return urls

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Check for HTTP Basic Auth on a list of URLs')
    parser.add_argument('url_file', type=str, help='File containing the list of URLs')
    parser.add_argument('--threads', type=int, default=20, help='Number of threads to use for checking URLs (default: 20)')
    args = parser.parse_args()

    urls = read_urls_from_file(args.url_file)
    print(f'[+] Loaded {len(urls)} URLs from {args.url_file}')

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(check_http_auth, url) for url in urls]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f'[!] Thread raised an exception: {e}')
