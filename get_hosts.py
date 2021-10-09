from scapy.all import *
import math

def long2net(arg):
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        return None

    return net


def scan_and_print_neighbors(net, interface, timeout=5):
    hosts = []
    try:
        ans, unans = arping(net, iface=interface, timeout=timeout, verbose=False)
        for s, r in ans.res:
            hosts.append(r.psrc)
        return hosts
    except Exception as e:
        return None


def get_all_hosts(interface_to_scan=None):

    for network, netmask, _, interface, address, _ in conf.route.routes:

        if interface_to_scan and interface_to_scan != interface:
            continue

        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        net = to_CIDR_notation(network, netmask)
        
        if net:
            return scan_and_print_neighbors(net, interface)
