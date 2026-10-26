#!/usr/bin/env python3

import argparse
import collections.abc
import ipaddress
import json
import pathlib
import socket
import subprocess

NUMBER = "+49 12 8378464 24"

#: enochecker_test names the team by the host's address on the default bridge,
#: which is what Docker resolves host-gateway to. The service never answers
#: there -- the checker calls it through the DSLAM -- but the number has to be
#: looked up under that address all the same.
HOST_ALIAS = "host.docker.internal"

def local_network_ipv4_addresses() -> collections.abc.Iterator[ipaddress.IPv4Address]:
    result = subprocess.run(["ip", "-j", "addr"], capture_output=True, check=True)
    network = json.loads(result.stdout)
    for iface in network:
        if iface["link_type"] == "loopback":
            continue
        for address in iface["addr_info"]:
            if address["scope"] != "global" or address["family"] != "inet":
                continue
            subnet = ipaddress.IPv4Interface((address["local"], address["prefixlen"]))
            yield from subnet.network

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", help="File to write the numbering plan to", type=pathlib.Path)
    args = parser.parse_args()

    with args.output.open("w") as output:
        # Random number allocations
        output.write("random:\n  prefix: \"+49 14 3272\"\n  length: 14\n\n")

        # Fixed number allocations: all IPs in the service network get the same number
        # This is technically a terrible idea.
        # But it works, as long as the CI only ever has one service container.
        output.write("fixed:\n")
        written = set()
        for ip in local_network_ipv4_addresses():
            written.add(ip)
            output.write(f"  \"{ip}\": \"{NUMBER}\"\n")

        try:
            host = ipaddress.IPv4Address(socket.gethostbyname(HOST_ALIAS))
        except (OSError, ipaddress.AddressValueError) as error:
            print(f"Not adding {HOST_ALIAS}: {error}")
        else:
            if host not in written:
                output.write(f"  \"{host}\": \"{NUMBER}\"\n")
