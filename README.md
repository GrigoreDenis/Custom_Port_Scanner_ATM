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