# modules
from concurrent.futures import ThreadPoolExecutor
import sys
from io import StringIO
import logging
import ipaddress
import sys
import threading
import os
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from scapy.layers.inet import Ether, IP, TCP, ICMP
from scapy.sendrecv import send, sr1
# get network address from arguments and validate it

try:
    network=sys.argv[1]
except:
    print("ERROR: Please introduce the network first!")
    quit()
ports = []
type_of_scan = -1
GLOBAL_TIME_OUT = 5
# -1 not defined
# 0 use half-connect TCP scan
# 1 use full-connect TCP scan
# 2 use UDP scan
# 3 use Stealth scan

# Check if arguments for -logs; -tcs,-ths,-udp,-sth; -p; -h;
if "-h" in sys.argv:
    print("Make sure the first argument is the network you're trying to scan, examples: 142.250.181.238 or 142.250.181.0/32")
    print("Use -logs in order to see more details as the program runs...")
    print("Use -tcs | -ths | -udp | -sth in order to define a type of scanning...")
    print("Use -p to define a range of ports, examples: -p80,443 (commas) or -p1-100 (hyphens) or -p1-100,400-500 (hybrid)")
    print("Use -timeout=# to define a global timeout to be used when scanning: \n \tLonger timeout => slower but higher chance of detection\n \tShorter timeout => faster but lower chance of detection")
    quit()


def check_scan_args():
    if type_of_scan!=-1:
        print("ERROR: Please use only one scan type")

if "-ths" in sys.argv:
    check_scan_args()
    type_of_scan=0

if "-tcs" in sys.argv:
    check_scan_args()
    type_of_scan=1

if type_of_scan == -1:
    print("Please use -tcs | -ths | -udp | -sth in order to define a type of scanning")
    quit()

if "-logs" in sys.argv:
    log_level=1
else:
    log_level=0

def log(string):
    if log_level ==1:
        print("LOG: %s" % string)


for port_argument in sys.argv:
    if "-timeout=" in port_argument:
        GLOBAL_TIME_OUT = int(port_argument.split("=")[1])
        print("Setting global timeout to: %d" % GLOBAL_TIME_OUT)

#PORT OPTIONS: -p80,443 (commas) or -p1-100 (hyphens) or -p1-100,400-500 (hybrid)
port_argument_found = False
for port_argument in sys.argv:
    if "-p" in port_argument:
        port_argument_found = True
        break;
if port_argument_found:
    aux_ports = (port_argument[2:]).split(",")
    hyphen_inside = False
    for port_range in aux_ports:
        if "-" in port_range:
            hyphen_inside = True
            ports_split = port_range.split("-")
            start = int(ports_split[0])
            end = int(ports_split[1])
            for i in range(start, end):
                ports.append(str(i))
        else:
            ports.append(port_range)
    if hyphen_inside == False:
        ports = aux_ports
    log("Using custom given ports: %s" % ports)
else:
    print("Using default ports")


#LOG OPTIONS: write -logs for more details




results = []
port_results = [[]]
####Thread function for pinging hosts:
def ThreadPing(host,t_id):
    log("Ping probing: %s" % host)
    command_string='ping -c 5 ' + str(host)
    tmp_res = os.popen(command_string)
    results[t_id]=(tmp_res.read())
    

# returns True if a connection can be made, False otherwise
def test_port_number(host,host_index, port,port_index):
####SYN-SCAN
    # create and configure the socket
    if type_of_scan==0:
        log("TCP half connect scanning host: %s" % host)
        ip=IP(dst=str(host))
        log("Attempting SYN Scan on port %s" % ports[port_index])
        tcp=TCP(dport=int(ports[port_index])) # defaults to flags: S for SYN
        packet = ip/tcp
        result=sr1(packet, timeout =GLOBAL_TIME_OUT,iface="eth0",verbose=False)
        #includes flags: SA for SYN-ACK
        #Redirect output of print to variable 'capture'
        try:
            answered = result[0]
            #unanswered = result[1]
            #capture = StringIO()
            #save_stdout = sys.stdout
            #sys.stdout = capture
            #answered.show()
            #sys.stdout = save_stdout
            capture = answered.show(dump=True)
            if "SA" in capture:
                port_results[host_index][port_index] = port
                log("Host %s /Port: %s responded with SYN-ACK"% (host,port))
            if "R" in capture:
                log("Host %s /Port: %s did not respond with SYN-ACK"% (host,port))
        except:
            log("Host %s /Port: %s did not respond at all"% (host,port,))
            pass
####CONNECT-SCAN
    elif type_of_scan==1:
        log("TCP full connect scanning port number: %s in host: %s" % (port,host))
        with socket(AF_INET, SOCK_STREAM) as sock:
            # set a timeout of a few seconds
            sock.settimeout(GLOBAL_TIME_OUT)
            # connecting may fail
            try:
                # attempt to connect
                sock.connect((host, int(port)))
                # a successful connection was made
                log("Host Succesfully connected to port: %s" % port)
                port_results[host_index][port_index]=port
            except:
                log("Host failed to connect to port: %s" % port)
                pass
    else:
        print("ERROR: type of scan undefined/wrong")
        quit()



####Thread function for full connection scanning hosts based on port:
def scan(host,host_index,ports):
    log("TCP full connect scanning: %s" % host)
    threads_scan = list()
    for port_index in range (len(ports)):
        thread_scan = threading.Thread(target=test_port_number, args=(host,host_index,ports[port_index],port_index,))
        threads_scan.append(thread_scan)
        thread_scan.start()
    for i,thread_scan in enumerate(threads_scan):
        thread_scan.join()






log("Identifying network version %s" % network)
try:
    ip_net = ipaddress.ip_network(network)
    print("IP address %s confirmed as IPv%s address" % (ip_net, ip_net.version))
except ValueError:
    print("Address/netmask is invalid: %s" % network)
    exit()
except:
    print("Usage : %s  ip" % sys.argv[0])
    exit()


print("Network given:\n",ip_net)

# get hosts
hosts = list(ip_net.hosts())

print("Hosts given:\n",hosts)

# For each IP address in the subnet, 
# run the ping command with threading.Thread
log("Starting ping probing")
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
log("Ending ping probing")
#if ports is empty, use default 1000 ports

if ports:
    print("Using custom ports")
else:
    file = open('top_1000_tcp_ports.txt', 'r') # get top 1000 tcp ports
    Lines = file.readlines()
    file.close()
    ports = Lines[0].split(",")

port_results = [[0]*len(ports)]*len(hosts)

##############################################################START TCP HALF CONNECT (SYN) SCAN
if type_of_scan==0:
    print("Executing Half-Connection (SYN) Scan")
    #executor = ThreadPoolExecutor(max_workers=2)
    for host_index in range (len(hosts)):
        thread = threading.Thread(target=scan, args=(str(hosts[host_index]),host_index,ports,))
        threads.append(thread)
        thread.start()
    for i,thread in enumerate(threads):
        thread.join()
        

##############################################################START TCP FULL CONNECT SCAN
if type_of_scan==1:
    print("Executing Full-Connection Scan")
    for host_index in range (len(hosts)):
        thread = threading.Thread(target=scan, args=(str(hosts[host_index]),host_index,ports,))
        threads.append(thread)
        thread.start()
    for i,thread in enumerate(threads):
        thread.join()


# Printing results for hosts and dicovered ports:

for host_index in range (len(hosts)):
    print("Open ports dicovered on host %s:" % hosts[host_index])
    print("PORT\tSTATE\tSERVICE\t")
    for port_index in range (len(ports)):
        if port_results[host_index][port_index]:
            print("%s\tOPEN\t...TODO...\t" % ports[port_index])
