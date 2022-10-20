# modules
import logging
import ipaddress
import sys
import threading
import os
####Thread function for pinging hosts:


results = []
def ThreadPing(host,t_id):
    command_string='ping -c 5 ' + str(host)
    tmp_res = os.popen(command_string)
    results[t_id]=(tmp_res.read())
    

# get network address from arguments and validate it

try:
    ip_net = ipaddress.ip_network(sys.argv[1])
    print("IP address %s confirmed as IPv%s address" % (ip_net, ip_net.version))
except ValueError:
    print("Address/netmask is invalid: %s" % sys.argv[1])
    exit()
except:
    print("Usage : %s  ip" % sys.argv[0])
    exit()


#ip = ipaddress.ip_address(sys.argv[1])
print("Network given:\n",ip_net)

# get hosts
hosts = list(ip_net.hosts())

print("Hosts given:\n",hosts)

# For each IP address in the subnet, 
# run the ping command with subprocess.popen interface

threads = list()
for i in range (len(hosts)):
    thread = threading.Thread(target=ThreadPing, args=(str(hosts[i]),i,))
    threads.append(thread)
    results.append(str(i))
    thread.start()

for i,thread in enumerate(threads):
    thread.join()

for i in range (len(results)):
    #print(str(results[i]))
    if "100% packet loss" in str(results[i]):
        print(str(hosts[i]), "is Offline")
    elif "Request timed out" in str(results[i]):
        print(str(hosts[i]), "is Offline")
    else:
        print(str(hosts[i]), "is Online")

import socket

