## Synchronize O365 routes to an IOS-XE router using Guest Shell
This Guest Shell script uses Microsoft O365 [Webservice](https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service) to get routing information of Office365 cloud. It can be used to automatically create static routes for a dedicated Internet link. So Office365 traffic will use the link and all the remaining traffic will be routed using a default route via a different link. It can be used as an alternative to [ExpressRoute](https://docs.microsoft.com/en-us/microsoft-365/enterprise/azure-expressroute). The generated static routes can be also used to bypass a firewall or proxy for Office365 traffic.

### Guest Shell configuration

IOS configuration
see https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1611/b_1611_programmability_cg/guest_shell.html
https://community.cisco.com/t5/developer-general-blogs/introducing-python-and-guest-shell-on-ios-xe-16-5/ba-p/3661394

```
iox
!
interface VirtualPortGroup0
 ip address 192.168.250.1 255.255.255.0
!
app-hosting appid guestshell
 app-vnic gateway0 virtualportgroup 0 guest-interface 0
  guest-ipaddress 192.168.250.2 netmask 255.255.255.0
 app-default-gateway 192.168.250.1 guest-interface 0
 name-server0 192.168.21.50
 start
```
VirtualPortGroup0 can have `ip nat inside` with proper additional configuration to provide NAT/PAT for the Guest Shell.

### Installation

1. start guest shell `guestshell run bash`
2. install git `sudo yum install git`
3. install Python virtualenv `sudo yum install python-virtualenv`
4. install script `git clone https://github.com/JardaMartan/o365-route.git`
5. `cd o365-route`
6. create Python virtual environment `virtualenv venv --system-site-packages`
7. switch to Python virtual environment `source venv/bin/activate`
8. install required packages `pip install -r requirements.txt`
9. run script in interactive mode `python o365_manage_route.py -i46`

### Automated run using EEM

EEM configuration to run every minute
```
event manager applet o365route
 event timer cron cron-entry "* * * * *"
 action 0.1 cli command "enable"
 action 1.0 syslog msg "O365 manage route script start"
 action 2.0 cli command "guestshell run ./o365-route/venv/bin/python ./o365-route/o365_manage_route.py -46"
 action 3.0 syslog msg "O365 manage route script end"
```

### Remove routes from configuration

1. run script in interactive mode `python -i o365_manage_route.py -i`
2. run test procedure `o365_networks, test_nets, cfg_nets = test_parsing()`
3. remove IPv4 and IPv6 routes `remove_routes(o365_networks["ipv4"], 4)`, `remove_routes(o365_networks["ipv6"], 6)`
4. do not forget to save configuration

for VRF-based configuration (VRF "vp" in this case) do:
1. `o365_networks, test_nets, cfg_nets = test_parsing(vrf="vp")`
2. `remove_routes(o365_networks["ipv4"], 4, vrf="vp")`
3. `remove_routes(o365_networks["ipv6"], 6, vrf="vp")`
