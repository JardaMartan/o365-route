""".
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses
               
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
__author__ = "Jaroslav Martan"
__email__ = "jmartan@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2020 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import uuid
import requests as req
import sys, os
import re
import ipaddress
from cli import cli,clip,configure,configurep, execute, executep
import config as cfg

# next-hop (default) gateways, set your next-hops for static routes here
if hasattr(cfg, "next_hops"):
    next_hops = cfg.next_hops
else:
    next_hops = {
        "ipv4": "192.168.25.1",
        "ipv6": "FD0C:F674:19EF:D2::1"
    }
    
check_v4_routes = cfg.check_v4_routes if hasattr(cfg, "check_v4_routes") else True
check_v6_routes = cfg.check_v6_routes if hasattr(cfg, "check_v6_routes") else False

def get_o365_networks(interactive = True):
    """Get list of Office365 networks from Microsoft
    see: https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service
    
    Args:
        interactive (bool): interactive mode (or automated), used for logging method
        
    Returns:
        dict with 2 lists of network prefixes (ipv4, ipv6).
    
    """
    my_uuid = str(uuid.uuid4())
    o365_endpoint_url = "https://endpoints.office.com/endpoints/worldwide"

    rurl = o365_endpoint_url+"?ClientRequestId="+my_uuid+"&format=JSON"

    res = req.get(rurl)
    if res.status_code != 200:
        log_message("O365 endpoints request failed with {} - {}".format(res.status_code, res.text), interactive)
        sys.exit()
    else:
        log_message("O365 endpoints fetch status code: {}".format(res.status_code), interactive)
        
    o365_endpoints = res.json()

    v4networks = []
    v6networks = []

    for e in o365_endpoints:
        if e["expressRoute"]:
            # print("{}: {} - {}".format(e["id"], e["category"], e["serviceAreaDisplayName"]))
            if e.get("ips"):
                result_ips = []
                for net in e["ips"]:
                    ip_net = ipaddress.ip_network(net)
                    if ip_net.version == 4:
                        v4networks.append(net)
                    elif ip_net.version == 6:
                        v6networks.append(net)
                    else:
                        log_message("Unknown IP version {} detected for {}".format(ip_net.version, net))
                
    v4nets = list(set(v4networks)) # remove duplicates
    v4nets.sort()
    v6nets = list(set(v6networks)) # remove duplicates
    v6nets.sort()
    
    return {"ipv4": v4nets, "ipv6": v6nets}

def create_ip_routes(networks, version, vrf = None, prefix="", interactive = True):
    """Create IOS CLI command(s) for static IP route setting
    
    Args:
        networks[] (str): list of network prefixes
        version (int): IP version (4/6)
        vrf (str): VRF name
        prefix (str): prefix before the command(s) - typically "no"
        interactive (bool): interactive mode (or automated), used for logging method
        
    Returns:
        Command string.
    
    """
    prefix = prefix.rstrip()
    if prefix:
        prefix += " "
        
    vrf_insert = "vrf {} ".format(vrf) if vrf else ""
    result = ""
    for net in networks:
        ip_net = ipaddress.ip_network(net)
        if ip_net.version == version:
            if ip_net.version == 4:
                result += "{}ip route {}{} {} {}\n".format(prefix, vrf_insert, ip_net.network_address, ip_net.netmask, next_hops["ipv4"])
            elif ip_net.version == 6:
                result += "{}ipv6 route {}{}/{} {}\n".format(prefix, vrf_insert, ip_net.network_address, ip_net.prefixlen, next_hops["ipv6"])
            else:
                log_message("invalid IP version {}, network: {}".format(ip_net.version, net), interactive)
                
    return result

def match_ipv4_route(route, vrf = None, skip_default_route = True):
    """Parse "ip route" command from IOS configuration
    
    Args:
        route (str): ip route command
        vrf (str): VRF name
        skip_default_route (bool): skip 0/0 route to avoid accidental default route deletion
        
    Returns:
        Network prefix string in "net/prefixlen" format.
    
    """
    vrf_insert = "vrf\\ {}\\ ".format(vrf) if vrf else ""
    match = re.findall(r"ip\ route\ {}([0-9.]+)\ ([0-9.]+)\ .*([0-9.]+)".format(vrf_insert), route)
    if match:
        addr, mask, gw = match[0]
        prefix = ipaddress.IPv4Network(u"{}/{}".format(addr, mask))
        if  prefix.prefixlen > 0 or not skip_default_route:
            return u"{}/{}".format(prefix.network_address, prefix.prefixlen)
            
def match_ipv6_route(route, vrf = None, skip_default_route = True):
    """Parse "ipv6 route" command from IOS configuration
    
    Args:
        route (str): ip route command
        vrf (str): VRF name
        skip_default_route (bool): skip 0::/0 route to avoid accidental default route deletion
        
    Returns:
        Network prefix string in "net/prefixlen" format.
    
    """
    vrf_insert = "vrf\\ {}\\ ".format(vrf) if vrf else ""
    match = re.findall(r"ipv6\ route\ {}([0-9a-fA-F:]+)\/([0-9]+)\ .*([0-9a-fA-F:]+)".format(vrf_insert), route)
    if match:
        addr, mask, gw = match[0]
        prefix = ipaddress.IPv6Network(u"{}/{}".format(addr, mask))
        if  prefix.prefixlen > 0 or not skip_default_route:
            return u"{}/{}".format(prefix.network_address, prefix.prefixlen)
                        
def get_configured_networks(vrf = None, interactive = True):
    """Get static routes from router configuration
    
Args:
    vrf (str): VRF name
    interactive (bool): interactive mode (or automated), used for logging method
    
Returns:
    dict with 2 lists of network prefixes (ipv4, ipv6).
    
    """
    v4cfg_nets = []
    v6cfg_nets = []
    vrf_insert = "vrf {}".format(vrf) if vrf else ""
    
    exec_result = execute("sh run | section ip route {}".format(vrf_insert))
    routes = exec_result.split("\n")
    
    for r in routes:
        netw = match_ipv4_route(r, vrf = vrf)
        if netw:
            v4cfg_nets.append(netw)
    
    exec_result = execute("sh run | section ipv6 route {}".format(vrf_insert))
    routes = exec_result.split("\n")
    
    for r in routes:
        netw = match_ipv6_route(r, vrf = vrf)
        if netw:
            v6cfg_nets.append(netw)
                
    return {"ipv4": v4cfg_nets, "ipv6": v6cfg_nets}
    
def compare_routes(o365_routes, configured_routes, interactive = True):
    """Compare list of routes from O365 and router
    
    Args:
            
    Returns:
        Networks that are missing in the router and that are excessive.
    
    """
    missing_routes = list(set(o365_routes) - set(configured_routes))
    excessive_routes = list(set(configured_routes) - set(o365_routes))
    
    return missing_routes, excessive_routes
    
def add_routes(routes, version, vrf = None, interactive = True):
    """Add routes to the router configuration
    
    Args:
        routes[] (str): list of routes to be added
        version (int): IP version (4/6)
        vrf (str): VRF name
        interactive (bool): run in interactive mode (ask user to confirm)
        
    Returns:
        IOS CLI command string.
    
    """
    if interactive:
        log_message("{} IPv{} routes to be added to VRF \"{}\": \n{}\n\n".format(len(routes), version, vrf, routes), interactive)
    else:
        log_message("{} IPv{} routes to be added to VRF \"{}\"".format(len(routes), version, vrf), interactive)
                
    response = raw_input("Perform action? y/N ") if interactive else "y"
    if response.lower() == "y":
        cmd = create_ip_routes(routes, version, vrf = vrf)
        
        return configure(cmd)
    
def remove_routes(routes, version, vrf = None, interactive = True):
    """Remove routes from the router configuration
    
    Args:
        routes[] (str): list of routes to be added
        version (int): IP version (4/6)
        vrf (str): VRF name
        interactive (bool): run in interactive mode (ask user to confirm)
        
    Returns:
        IOS CLI command string.
    
    """
    if interactive:
        log_message("{} IPv{} routes to be removed fro VRF  \"{}\": \n{}\n\n".format(len(routes), version, vrf, routes), interactive)
    else:
        log_message("{} IPv{} routes to be removed from VRF \"{}\"".format(len(routes), version, vrf), interactive)

    response = raw_input("Perform action? y/N ") if interactive else "y"
    if response.lower() == "y":
        cmd = create_ip_routes(routes, version, vrf = vrf, prefix = "no")
        
        return configure(cmd)
        
def log_message(message, interactive = True):
    if interactive:
        print(message)
    else:
        ios_log(message)
        
def ios_log(message, severity=5):
    # !!! do not send large messages to the log !!!
    message = (message[:120] + '...') if len(message) > 120 else message
    cli("send log {} {}".format(severity, message))
        
def test_parsing(vrf = None):
    """Test procedure to verify O365 source and parsing commands
    
    Args:
        
    Returns:
        O365 networks, test networks (should be the same as O365), static networks from the router.
    
    """
    o365_networks = get_o365_networks()
    configured_networks = get_configured_networks(vrf = vrf)

    v4nets = o365_networks["ipv4"]
    nets = v4nets

    cmd = create_ip_routes(v4nets, 4, vrf = vrf)
    rt = cmd.split("\n")
    v4test_nets = []
    test_nets = v4test_nets
    for r in rt:
        netw = match_ipv4_route(r, vrf = vrf)
        if netw:
            v4test_nets.append(netw)
            
    compare_1 = list(set(v4nets) - set(v4test_nets))
    compare_2 = list(set(v4test_nets) - set(v4nets))
    
    if compare_1 or compare_2:
        log_message("IPv4 test failed, non-empty results\n1: {},\n 2: {}".format(compare_1, compare_2))
    else:
        log_message("IPv4 test OK, networks received, command parsing passed")

    v6nets = o365_networks["ipv6"]
    cmd = create_ip_routes(v6nets, 6, vrf = vrf)
    rt = cmd.split("\n")
    v6test_nets = []
    test_nets += v6test_nets
    for r in rt:
        netw = match_ipv6_route(r, vrf = vrf)
        if netw:
            v6test_nets.append(netw)
            
    compare_1 = list(set(v6nets) - set(v6test_nets))
    compare_2 = list(set(v6test_nets) - set(v6nets))
    
    if compare_1 or compare_2:
        log_message("IPv6 test failed, non-empty results\n1: {},\n 2: {}".format(compare_1, compare_2))
    else:
        log_message("IPv6 test OK, networks received, command parsing passed")

    cfg_nets = get_configured_networks(vrf = vrf)
    log_message("Configured networks: {}".format(cfg_nets))
    
    test_nets = {"ipv4": v4test_nets, "ipv6": v6test_nets}
    
    return o365_networks, test_nets, cfg_nets
    
"""
To run tests or delete existing routes, switch to interactive mode

python -i o365_manage_route.py -i

and do:

o365_networks, test_nets, cfg_nets = test_parsing()

remove_routes(o365_networks["ipv4"], 4)

remove_routes(o365_networks["ipv6"], 6)


or for VRF-based configuration (VRF "vp" in this case):

o365_networks, test_nets, cfg_nets = test_parsing(vrf="vp")

remove_routes(o365_networks["ipv4"], 4, vrf="vp")

remove_routes(o365_networks["ipv6"], 6, vrf="vp")
"""
            
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("-4", "--ipv4", action="store_true", help="Check IPv4 routing information (default yes)", default = check_v4_routes)
    parser.add_argument("-6", "--ipv6", action="store_true", help="Check IPv6 routing information (default no)", default = check_v6_routes)
    parser.add_argument("-v", "--vrf", type = str, help="VRF name")

    args = parser.parse_args()
    if not args.ipv4:
        check_v4_routes = False
    if args.ipv6:
        check_v6_routes = True
        
    o365_networks = get_o365_networks(args.interactive)
    configured_networks = get_configured_networks(vrf = args.vrf, interactive = args.interactive)

    config_changed = False
    if check_v4_routes:
        response = raw_input("Check IPv4 O365 routing configuration? y/N ") if args.interactive else "y"
        if response.lower() == "y":
            v4missing, v4excessive = compare_routes(o365_networks["ipv4"], configured_networks["ipv4"], interactive = args.interactive)
            
            if v4missing:
                add_result = add_routes(v4missing, 4, vrf = args.vrf, interactive = args.interactive)
                config_changed = True
            else:
                log_message("No IPv4 routes to be added to VRF \"{}\"".format(args.vrf), interactive = args.interactive)

            if v4excessive:
                remove_result = remove_routes(v4excessive, 4, vrf = args.vrf, interactive = args.interactive)
                config_changed = True
            else:
                log_message("No IPv4 routes to be removed from VRF \"{}\"".format(args.vrf), interactive = args.interactive)

    if check_v6_routes:
        response = raw_input("Check IPv6 O365 routing configuration? y/N ") if args.interactive else "y"
        if response.lower() == "y":
            v6missing, v6excessive = compare_routes(o365_networks["ipv6"], configured_networks["ipv6"], interactive = args.interactive)
            
            if v6missing:
                add_result = add_routes(v6missing, 6, vrf = args.vrf, interactive = args.interactive)
                config_changed = True
            else:
                log_message("No IPv6 routes to be added to VRF \"{}\"".format(args.vrf), interactive = args.interactive)

            if v6excessive:
                remove_result = remove_routes(v6excessive, 6, vrf = args.vrf, interactive = args.interactive)
                config_changed = True
            else:
                log_message("No IPv6 routes to be removed from VRF \"{}\"".format(args.vrf), interactive = args.interactive)

    if config_changed:
        response = raw_input("Save configuration? y/N ") if args.interactive else "y"
        log_message("Saving configuration...", interactive = args.interactive)
        if response.lower() == "y":
            save_result = execute("copy run start")
