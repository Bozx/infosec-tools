import argparse
import ipaddress
from ping3 import ping
from concurrent.futures import ThreadPoolExecutor

# Default CIDR ranges
default_cidrs = [
    '2a06:d581:2000::/36',
    '2a06:d581:1000::/36',
    '194.38.224.0/19',
    '159.103.229.0/24',
    '159.103.214.94/32',
    '159.103.214.139/32',
    '159.103.210.103/32',
    '159.103.208.0/24',
    '159.103.207.0/24',
    '159.103.127.0/24'
]

def check_host_alive(ip):
    try:
        res = ping(str(ip))
        if res is not None:
            print(f'{ip} is alive')
        else:
            print(f'{ip} is dead')
    except Exception as e:
        print(f"Error pinging {ip}: {e}")

def check_cidr_alive(cidr):
    net = ipaddress.ip_network(cidr)
    hosts = net.hosts() if net.num_addresses <= 1024 else net.hosts()[:1024]
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(check_host_alive, hosts)

def read_cidrs_from_file(file_path):
    with open(file_path, 'r') as f:
        cidrs = [line.strip() for line in f]
    return cidrs

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check if hosts in CIDR ranges are alive.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File containing CIDR ranges.')
    group.add_argument('-h', '--host', help='Single CIDR to check.')
    args = parser.parse_args()

    if args.file:
        cidrs = read_cidrs_from_file(args.file)
        for cidr in cidrs:
            check_cidr_alive(cidr)
    elif args.host:
        check_cidr_alive(args.host)
