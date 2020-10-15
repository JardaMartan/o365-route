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
if hasattr(cfg, "default_gws"):
    default_gws = cfg.default_gws
else:
    default_gws = {
        4: "192.168.25.1",
        6: "FD0C:F674:19EF:D2::1"
    }
    
check_v4_routes = cfg.check_v4_routes if hasattr(cfg, "check_v4_routes") else True
check_v6_routes = cfg.check_v6_routes if hasattr(cfg, "check_v6_routes") else False

def get_o365_networks(v4 = True, v6 = False, interactive = True):
    """Get list of Office365 networks from Microsoft
    see: https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service
    
    Args:
        v4 (bool): return IPv4 networks
        v6 (bool): return IPv6 networks
        
    Returns:
        List of network prefixes.
    
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

    networks = []

    for e in o365_endpoints:
        if e["expressRoute"]:
            # print("{}: {} - {}".format(e["id"], e["category"], e["serviceAreaDisplayName"]))
            if e.get("ips"):
                result_ips = []
                for net in e["ips"]:
                    ip_net = ipaddress.ip_network(net)
                    if (ip_net.version == 4 and v4) or (ip_net.version == 6 and v6):
                        networks.append(net)
                
    nets = list(set(networks))
    nets.sort()
    
    return nets

def create_ip_routes(networks, version, prefix="", interactive = True):
    """Create IOS CLI command(s) for static IP route setting
    
    Args:
        networks[] (str): list of network prefixes
        version (int): IP version (4/6)
        prefix (str): prefix before the command(s) - typically "no"
        
    Returns:
        Command string.
    
    """
    prefix = prefix.rstrip()
    if prefix:
        prefix += " "
    result = ""
    for net in networks:
        ip_net = ipaddress.ip_network(net)
        if ip_net.version == version:
            if ip_net.version == 4:
                result += "{}ip route {} {} {}\n".format(prefix, ip_net.network_address, ip_net.netmask, default_gws[4])
            elif ip_net.version == 6:
                result += "{}ipv6 route {}/{} {}\n".format(prefix, ip_net.network_address, ip_net.prefixlen, default_gws[6])
            else:
                log_message("invalid IP version {}, network: {}".format(ip_net.version, net), interactive)
                
    return result

def match_ipv4_route(route, skip_default_route = True):
    """Parse "ip route" command from IOS configuration
    
    Args:
        route (str): ip route command
        skip_default_route (bool): skip 0/0 route to avoid accidental default route deletion
        
    Returns:
        Network prefix string in "net/prefixlen" format.
    
    """
    match = re.findall(r"ip\ route\ ([0-9.]+)\ ([0-9.]+)\ .*([0-9.]+)", route)
    if match:
        addr, mask, gw = match[0]
        prefix = ipaddress.IPv4Network(u"{}/{}".format(addr, mask))
        if  prefix.prefixlen > 0 or not skip_default_route:
            return u"{}/{}".format(prefix.network_address, prefix.prefixlen)
            
def match_ipv6_route(route, skip_default_route = True):
    """Parse "ipv6 route" command from IOS configuration
    
    Args:
        route (str): ip route command
        skip_default_route (bool): skip 0::/0 route to avoid accidental default route deletion
        
    Returns:
        Network prefix string in "net/prefixlen" format.
    
    """
    match = re.findall(r"ipv6\ route\ ([0-9a-fA-F:]+)\/([0-9]+)\ .*([0-9a-fA-F:]+)", route)
    if match:
        addr, mask, gw = match[0]
        prefix = ipaddress.IPv6Network(u"{}/{}".format(addr, mask))
        if  prefix.prefixlen > 0 or not skip_default_route:
            return u"{}/{}".format(prefix.network_address, prefix.prefixlen)
                        
def get_configured_networks(v4 = True, v6 = False, interactive = True):
    """Get static routes from router configuration
    
    Args:
        
    Returns:
        List of routes in "net/prefixlen" format.
    
    """
    cfg_nets = []
    
    if v4:
        exec_result = execute("sh run | section ip route")
        routes = exec_result.split("\n")
        
        for r in routes:
            netw = match_ipv4_route(r)
            if netw:
                cfg_nets.append(netw)
    
    if v6:
        exec_result = execute("sh run | section ipv6 route")
        routes = exec_result.split("\n")
        
        for r in routes:
            netw = match_ipv6_route(r)
            if netw:
                cfg_nets.append(netw)
                
    return cfg_nets
    
def compare_routes(v4 = True, v6 = False, interactive = True):
    """Compare list of routes from O365 and router
    
    Args:
            
    Returns:
        Networks that are missing in the router and that are excessive.
    
    """
    o365_routes = get_o365_networks(v4, v6, interactive)
    configured_routes = get_configured_networks(v4, v6, interactive)
    
    missing_routes = list(set(o365_routes) - set(configured_routes))
    excessive_routes = list(set(configured_routes) - set(o365_routes))
    
    return missing_routes, excessive_routes
    
def add_routes(routes, version, interactive = True):
    """Add routes to the router configuration
    
    Args:
        routes[] (str): list of routes to be added
        version (int): IP version (4/6)
        interactive: run in interactive mode (ask user to confirm)
        
    Returns:
        IOS CLI command string.
    
    """
    if interactive or routes:
        log_message("{} routes to be added: \n{}\n\n".format(len(routes), routes), interactive)
    elif not routes:
        log_message("No routes to be added", interactive)
        return ""
                
    response = raw_input("Perform action? y/N ") if interactive else "y"
    if response.lower() == "y":
        cmd = create_ip_routes(routes, version)
        
        return configure(cmd)
    
def remove_routes(routes, version, interactive = True):
    """Remove routes from the router configuration
    
    Args:
        routes[] (str): list of routes to be added
        version (int): IP version (4/6)
        
    Returns:
        IOS CLI command string.
    
    """
    if interactive or routes:
        log_message("{} routes to be removed: \n{}\n\n".format(len(routes), routes), interactive)
    elif not routes:
        log_message("No routes to be removed", interactive)
        return ""

    response = raw_input("Perform action? y/N ") if interactive else "y"
    if response.lower() == "y":
        cmd = create_ip_routes(routes, version, "no")
        
        return configure(cmd)
        
def log_message(message, interactive = True):
    if interactive:
        print(message)
    else:
        ios_log(message)
        
def ios_log(message, severity=5):
    cli("send log {} {}".format(severity, message))
        
def test_parsing():
    """Test procedure to verify O365 source and parsing commands
    
    Args:
        
    Returns:
        O365 networks, test networks (should be the same as O365), static networks from the router.
    
    """
    v4nets = get_o365_networks(v4 = True, v6 = False)
    nets = v4nets

    cmd = create_ip_routes(v4nets, 4)
    rt = cmd.split("\n")
    v4test_nets = []
    test_nets = v4test_nets
    for r in rt:
        netw = match_ipv4_route(r)
        if netw:
            v4test_nets.append(netw)
            
    compare_1 = list(set(v4nets) - set(v4test_nets))
    compare_2 = list(set(v4test_nets) - set(v4nets))
    
    if compare_1 or compare_2:
        log_message("IPv4 test failed, non-empty results\n1: {},\n 2: {}".format(compare_1, compare_2))
    else:
        log_message("IPv4 test OK, networks received, command parsing passed")

    v6nets = get_o365_networks(v4 = False, v6 = True)
    nets += v6nets   
    cmd = create_ip_routes(v6nets, 6)
    rt = cmd.split("\n")
    v6test_nets = []
    test_nets += v6test_nets
    for r in rt:
        netw = match_ipv6_route(r)
        if netw:
            v6test_nets.append(netw)
            
    compare_1 = list(set(v6nets) - set(v6test_nets))
    compare_2 = list(set(v6test_nets) - set(v6nets))
    
    if compare_1 or compare_2:
        log_message("IPv6 test failed, non-empty results\n1: {},\n 2: {}".format(compare_1, compare_2))
    else:
        log_message("IPv6 test OK, networks received, command parsing passed")

    cfg_nets = get_configured_networks(v4 = True, v6 = True)
    log_message("Configured networks: {}".format(cfg_nets))
    
    return nets, test_nets, cfg_nets
            
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("-4", "--ipv4", action="store_true", help="Check IPv4 routing information (default yes)")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Check IPv6 routing information (default no)")

    args = parser.parse_args()
    if not args.ipv4:
        check_v4_routes = False
    if args.ipv6:
        check_v6_routes = True
    if args.interactive:
        if check_v4_routes:
            response = raw_input("Check IPv4 O365 routing configuration? y/N ")
            if response.lower() == "y":
                v4missing, v4excessive = compare_routes(v4 = True, v6 = False, interactive = args.interactive)
                
                add_result = add_routes(v4missing, 4)
                remove_result = remove_routes(v4excessive, 4)

        if check_v6_routes:
            response = raw_input("Check IPv6 O365 routing configuration? y/N ")
            if response.lower() == "y":
                v6missing, v6excessive = compare_routes(v4 = False, v6 = True, interactive = args.interactive)
                
                add_result = add_routes(v6missing, 6)
                print()
                remove_result = remove_routes(v6excessive, 6)
            
        response = raw_input("Save configuration? y/N ")
        if response.lower() == "y":
            save_result = execute("copy run start")
    else:
        config_changed = False
        if check_v4_routes:
            v4missing, v4excessive = compare_routes(v4 = True, v6 = False, interactive = False)

            if v4missing:
                add_result = add_routes(v4missing, 4, interactive = False)
                config_changed = True
            else:
                ios_log("No IPv4 routes to be added")
                
            if v4excessive:
                remove_result = remove_routes(v4excessive, 4, interactive = False)
                config_changed = True
            else:
                ios_log("No IPv4 routes to be removed")

        if check_v6_routes:
            v6missing, v6excessive = compare_routes(v4 = False, v6 = True, interactive = False)

            if v6missing:
                add_result = add_routes(v6missing, 6, interactive = False)
                config_changed = True
            else:
                ios_log("No IPv6 routes to be added")
                
            if v6excessive:
                remove_result = remove_routes(v6excessive, 6, interactive = False)
                config_changed = True
            else:
                ios_log("No IPv6 routes to be removed")
                
        if config_changed:
            ios_log("Saving configuration...")
            save_result = execute("copy run start")
