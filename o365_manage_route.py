import uuid
import requests as req
import sys, os
import re
import ipaddress
from cli import cli,clip,configure,configurep, execute, executep

default_gws = {
4: "192.168.25.1",
6: "FD0C:F674:19EF:D2::1"
}

def get_o365_networks(v4 = True, v6 = False):
    my_uuid = str(uuid.uuid4())
    o365_endpoint_url = "https://endpoints.office.com/endpoints/worldwide"

    rurl = o365_endpoint_url+"?ClientRequestId="+my_uuid+"&format=JSON"

    res = req.get(rurl)
    if res.status_code != 200:
        print("O365 endpoints request failed with {} - {}".format(res.status_code, res.text))
        sys.exit()
        
    o365_endpoints = res.json()

    networks = []

    for e in o365_endpoints:
        if e["expressRoute"]:
            print("{}: {} - {}".format(e["id"], e["category"], e["serviceAreaDisplayName"]))
            if e.get("ips"):
                result_ips = []
                for net in e["ips"]:
                    ip_net = ipaddress.ip_network(net)
                    if (ip_net.version == 4 and v4) or (ip_net.version == 6 and v6):
                        networks.append(net)
                
    nets = list(set(networks))
    nets.sort()
    
    return nets

def create_ip_routes(networks, version, prefix=""):
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
                print("invalid IP version {}, network: {}".format(ip_net.version, net))
                continue
            
            if prefix:
                result = prefix + " " + result
                
    return result

def match_ipv4_route(route, skip_default_route = True):
    match = re.findall(r"ip\ route\ ([0-9.]+)\ ([0-9.]+)\ .*([0-9.]+)", route)
    if match:
        addr, mask, gw = match[0]
        prefix = ipaddress.IPv4Network(u"{}/{}".format(addr, mask))
        if  prefix.prefixlen > 0 or not skip_default_route:
            return u"{}/{}".format(prefix.network_address, prefix.prefixlen)
            
def get_configured_networks():
    exec_result = execute("sh run | section ip route")
    routes = exec_result.split("\n")
    
    cfg_nets = []
    for r in routes:
        netw = match_ipv4_route(r)
        if netw:
            cfg_nets.append(netw)
    
    return cfg_nets
    
def compare_routes():
    o365_routes = get_o365_networks()
    configured_routes = get_configured_networks()
    
    missing_routes = list(set(o365_routes) - set(configured_routes))
    excessive_routes = list(set(configured_routes) - set(o365_routes))
    return missing_routes, excessive_routes
    
def add_routes(routes, version):
    print("Routes to be added: \n{}\n\n".format(routes))
    response = raw_input("Perform action? y/N ")
    if response.lower() == "y":
        cmd = create_ip_routes(routes, version)
        
        return cmd
    
def remove_routes(routes, version):
    print("Routes to be added: \n{}\n\n".format(routes))
    response = raw_input("Perform action? y/N ")
    if response.lower() == "y":
        cmd = create_ip_routes(routes, version, "no")
        
        return cmd
            
if __name__ == "__main__":
    nets = get_o365_networks()
    
    for ver in [4, 6]:
        print("version {} routes:".format(ver))
        
        print(create_ip_routes(nets, ver))
                    
        print

    cmd = create_ip_routes(nets, 4)
    rt = cmd.split("\n")
    test_nets = []
    for r in rt:
        netw = match_ipv4_route(r)
        if netw:
            test_nets.append(netw)

    cfg_nets = get_configured_networks()
