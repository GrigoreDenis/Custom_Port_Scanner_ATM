 Make sure the first argument is the network you're trying to scan, examples: 142.250.181.238 or 142.250.181.0/32
 Use -logs in order to see more details as the program runs...
 Use -tcs | -ths | -udp | -sth in order to define a type of scanning...
 Use -p to define a range of ports, examples: -p80,443 (commas) or -p1-100 (hyphens) or -p1-100,400-500 (hybrid)

-tcs -> TCP Connect Scan
-ths -> TCP Half-open Scan
-udp -> UDP scan
-sth -> Stealth Scan

1) Pings the IP to make sure it's alive
    if it is NOT online 
        -> throws appropriate message
    else
        -> Proceed to next step

2) Start TCP Half-Open scan

3) Start TCP connect



4) Start UDP scan

5) Attempt Stealth Scan (argument based)

A port scan is a method for determining which ports on a network are open. As ports on a computer are the place where information is sent and received, port scanning is analogous to knocking on doors to see if someone is home.

The goal behind port and network scanning is to identify the organization of IP addresses, hosts, and ports to properly determine open or vulnerable server locations and diagnose security levels.

PING SCAN. Ping Scans are used to sweep a whole network block or a single target to check to see if the target is alive. ...
TCP Half-Open. This is probably the most common type of port scan. ...
TCP CONNECT. ...
UDP. ...
STEALTH SCANNING – NULL, FIN, X-MAS.

One of the more common and popular port scanning techniques is the TCP half-open port scan, sometimes referred to as an SYN scan. It's a fast and sneaky scan that tries to find potential open ports on the target computer. SYN packets request a response from a computer, and an ACK packet is a response

Types of tcp scan defined in global variable:
-1 not defined
0 use half-connect TCP scan
1 use full-connect TCP scan
2 use UDP scan
3 use Stealth scan