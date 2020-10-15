## Synchronize O365 routes to an IOS-XE router using Guest Shell

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
2. install git `yum install git`
3. install script `git clone https://github.com/JardaMartan/o365-route.git`
4. `cd o365-route`
5. install Python virtual environment `python -m virtualenv venv`
6. switch to Python virtual environment `source venv/bin/activate`
7. install required packages `pip install -r requirements.txt`
8. run script in interactive mode `python o365_manage_route.py -i46`

### Automated run using EEM

EEM configuration
```
event manager applet o365route
 event timer cron cron-entry "* * * * *"
 action 0.1 cli command "enable"
 action 1.0 syslog msg "O365 manage route script start"
 action 2.0 cli command "guestshell run ./o365-route/venv/bin/python ./o365-route/o365_manage_route.py -46"
 action 3.0 syslog msg "O365 manage route script end"
```
