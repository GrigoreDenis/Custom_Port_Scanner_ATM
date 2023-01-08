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
from socket import getservbyport
import requests
from time import sleep
#from custom_port_scanner import ThreadPing
from scapy.layers.inet import Ether, IP, TCP, ICMP, UDP
from scapy.sendrecv import send, sr1
from scapy.all import RandShort
import logger

    #def DNS_Check_Alive_Hosts():
        #TODO

class Port_Scanner:
    semaphore = threading.Semaphore(5) #permitem doar 5 de threaduri la rularea HALF CONNECT, comportament impredictibil altfel....
    semaphoreUDP = threading.Semaphore(100)
    ports = []
    type_of_scan = -1
    GLOBAL_TIME_OUT = 5
    hosts = []
    results = []
    os_results=[]
    port_results = [[]]
    service_results = [[]]
    def check_scan_args(self):
        if self.type_of_scan!=-1:
            print("ERROR: Please use only one scan type")
            exit()

    def __init__(self, network, arguments_system): #Give network for the constructor
        if "-h" in arguments_system:
            print("Make sure the first argument is the network you're trying to scan, examples: 142.250.181.238 or 142.250.181.0/32")
            print("Use -logs in order to see more details as the program runs...")
            print("Use -tcs | -ths | -udp | -sth in order to define a type of scanning...")
            print("Use -p to define a range of ports, examples: -p80,443 (commas) or -p1-100 (hyphens) or -p1-100,400-500 (hybrid)")
            print("Use -timeout=# to define a global timeout to be used when scanning: \n \tLonger timeout => slower but higher chance of detection\n \tShorter timeout => faster but lower chance of detection")
            quit()
        if "-timeout=" in arguments_system:
            self.GLOBAL_TIME_OUT = int(arguments_system.split("=")[1])
            print("Setting global timeout to: %d" % self.GLOBAL_TIME_OUT)

        if "-logs" in arguments_system:
            log_level=1
        else:
            log_level=0
        self.ps_logger=logger.logger(log_level)
        self.ps_logger.log("Identifying network version %s" % network)
        try:
            ip_net = ipaddress.ip_network(network)
            print("IP address %s confirmed as IPv%s address" % (ip_net, ip_net.version))
        except ValueError:
            print("Address/netmask is invalid: %s" % network)
            exit()


        print("Network given:\n",ip_net)

        # get hosts
        self.hosts = list(ip_net.hosts())

        print("Hosts given:\n",self.hosts)
        self.os_results=[0]*len(self.hosts)

        if "-ths" in arguments_system:
            self.check_scan_args()
            self.type_of_scan=0

        if "-tcs" in arguments_system:
            self.check_scan_args()
            self.type_of_scan=1
        if "-udp" in arguments_system:
            self.check_scan_args()
            self.type_of_scan=2

        if self.type_of_scan == -1:
            print("Please use -tcs | -ths | -udp | -sth in order to define a type of scanning")
            quit()

        self.GLOBAL_TIME_OUT = 5
    
    def Set_Time_Out(self,timeout):
        self.GLOBAL_TIME_OUT=timeout
    def Get_Port_Arguments(self,port_argument):
        #PORT OPTIONS: -p80,443 (commas) or -p1-100 (hyphens) or -p1-100,400-500 (hybrid)
        port_argument_found = False
        for ports in port_argument:
            if "-p" in ports:
                port_argument_found = True
                break;
        if port_argument_found:
            aux_ports = (ports[2:]).split(",")
            hyphen_inside = False
            for port_range in aux_ports:
                if "-" in port_range:
                    hyphen_inside = True
                    ports_split = port_range.split("-")
                    start = int(ports_split[0])
                    end = int(ports_split[1])
                    for i in range(start, end):
                        self.ports.append(str(i))
                else:
                    self.ports.append(port_range)
            if hyphen_inside == False:
                self.ports = aux_ports
            self.ps_logger.log("Using custom given ports: %s" % self.ports)
        else:
            print("Using default ports, no -p found in given argument")
            self.Use_Default_1000_Ports()
        self.port_results = [[0]*len(self.ports)]*len(self.hosts)
        self.service_results = [[0]*len(self.ports)]*len(self.hosts)

    def Use_Default_1000_Ports(self):
        #Based on the type of scan that needs to be done (TCP or UDP)
        if self.type_of_scan==0 or self.type_of_scan==1: #TCP
            file = open('top_1000_tcp_ports.txt', 'r') # get top 1000 tcp ports
            Lines = file.readlines()
            file.close()
            self.ports = Lines[0].split(",")
        elif self.type_of_scan==2: #UDP
            file = open('top_1000_udp_ports.txt', 'r') # get top 1000 udp ports
            Lines = file.readlines()
            file.close()
            self.ports = Lines[0].split(",")

    def __ThreadPing(self,host,t_id):
        self.ps_logger.log("Ping probing: %s" % host)
        command_string='ping -c 5 ' + str(host)
        tmp_res = os.popen(command_string)
        self.results[t_id]=(tmp_res.read())

    def Ping_Scan_Hosts(self):
        self.ps_logger.log("Starting ping probing")
        threads = list()
        for i in range (len(self.hosts)):
            thread = threading.Thread(target=self.__ThreadPing, args=(str(self.hosts[i]),i,))
            threads.append(thread)
            self.results.append(str(i))
            thread.start()

        for i,thread in enumerate(threads):
            thread.join()

        for i in range (len(self.results)):
            #print(str(results[i]))
            if "100% packet loss" in str(self.results[i]):
                print(str(self.hosts[i]), "is Offline")
            elif "Request timed out" in str(self.results[i]):
                print(str(self.hosts[i]), "is Offline")
            else:
                print(str(self.hosts[i]), "is Online")
        self.ps_logger.log("Ending ping probing")
        self.__Get_Operating_System()
    def Print_Results(self):
        for host_index in range (len(self.hosts)):
            print("Open ports dicovered on host %s \nWith operating system %s:" % (self.hosts[host_index], self.os_results[host_index]))
            print("PORT\tSTATE\tSERVICE\t")
            for port_index in range (len(self.ports)):
                if self.port_results[host_index][port_index]:
                    print("%s\tOPEN\t%s\t" % (self.ports[port_index],self.service_results[host_index][port_index]))
    def __test_port_number(self,host,host_index, port,port_index):
        ####SYN-SCAN
        # create and configure the socket
        if self.type_of_scan==0:
            self.ps_logger.log("TCP half connect scanning host: %s" % host)
            ip=IP(dst=str(host))
            self.ps_logger.log("Attempting SYN Scan on port %s" % self.ports[port_index])
            tcp=TCP(dport=int(self.ports[port_index]),flags="S") # defaults to flags: S for SYN
            packet = ip/tcp
            result=sr1(packet, timeout =5,iface="eth0",verbose=False) # GLOBAL_TIMEOUT DOESN'T APPLY HERE
            #includes flags: SA for SYN-ACK
            #Redirect output of print to variable 'capture'
            self.semaphore.acquire()
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
                    self.port_results[host_index][port_index] = port
                    self.ps_logger.log("Host %s /Port: %s responded with SYN-ACK"% (host,port))
                if "R" in capture:
                    self.ps_logger.log("Host %s /Port: %s did not respond with SYN-ACK"% (host,port))
            except:
                self.ps_logger.log("Host %s /Port: %s did not respond at all"% (host,port,))
                pass
            finally:
                self.semaphore.release()
    ####CONNECT-SCAN
        elif self.type_of_scan==1:
            self.ps_logger.log("TCP full connect scanning port number: %s in host: %s" % (port,host))
            with socket(AF_INET, SOCK_STREAM) as sock:
                # set a timeout of a few seconds
                sock.settimeout(self.GLOBAL_TIME_OUT)
                # connecting may fail
                try:
                    # attempt to connect
                    sock.connect((host, int(port)))
                    # a successful connection was made
                    self.ps_logger.log("Succesfully connected to TCP port: %s" % port)
                    self.port_results[host_index][port_index]=port
                except:
                    self.ps_logger.log("Failed to connect to TCP port: %s" % port)
                    pass
    ####UDP SCAN --------- TO BE TESTED
        elif self.type_of_scan==2:
            self.semaphoreUDP.acquire()
            self.ps_logger.log("UDP scanning port number: %s in host: %s" % (port,host))
            ip_scan_packet = IP(dst=str(host))
            udp_scan_packet = UDP(dport=int(self.ports[port_index]))
            scan_packet = ip_scan_packet/udp_scan_packet
            scan_response = sr1(scan_packet,timeout=5,verbose=0)
            try:
                if scan_response is None:
                    if len(scan_response)==0:
                        self.ps_logger.log("We found UDP port: %s to be filtered" % port)
                    else:
                        self.ps_logger.log("Succesfully connected to UDP port: %s" % port)
                        self.port_results[host_index][port_index]=port
                else:
                    self.ps_logger.log("We found UDP port: %s to be closed" % port)
            except:
                self.ps_logger.log("We found UDP port: %s to be closed" % port)
                pass
            finally:
                self.semaphoreUDP.release()
        else:
            print("ERROR: type of scan undefined/wrong")
            quit()



    def __scan(self,host,host_index,ports):
        self.ps_logger.log("TCP full connect scanning: %s" % host)
        threads_scan = list()
        for port_index in range (len(ports)):
            thread_scan = threading.Thread(target=self.__test_port_number, args=(host,host_index,ports[port_index],port_index,))
            threads_scan.append(thread_scan)
            thread_scan.start()
        for i,thread_scan in enumerate(threads_scan):
            thread_scan.join()

    def Start_Port_Scanning(self):
        threads = list()

        ##############################################################START TCP HALF CONNECT (SYN) SCAN
        #if self.type_of_scan==0:
        #    print("Executing Half-Connection (SYN) Scan")
        #    #executor = ThreadPoolExecutor(max_workers=2)
        #    for host_index in range (len(self.hosts)):
        #        thread = threading.Thread(target=self.__scan, args=(str(self.hosts[host_index]),host_index,self.ports,))
        #        threads.append(thread)
        #        thread.start()
        #    for i,thread in enumerate(threads):
         #       thread.join()
                

        ##############################################################START TCP FULL CONNECT SCAN
        if self.type_of_scan==1:
            print("Executing TCP Full-Connection Scan")
        if self.type_of_scan==0:
            print("Executing TCP Half-Connection (SYN) Scan")
        if self.type_of_scan==2:
            print("Executing UDP Scan")
        for host_index in range (len(self.hosts)):
            
            thread = threading.Thread(target=self.__scan, args=(str(self.hosts[host_index]),host_index,self.ports,))
            threads.append(thread)
            thread.start()
        for i,thread in enumerate(threads):
            thread.join()

        self.__Get_Services_Running()


    def __Get_Operating_System(self):
        for host_index in range(len(self.hosts)):
            os = ''
            target = str(self.hosts[host_index])
            pack = IP(dst=target)/ICMP()
            resp = sr1(pack, timeout=3)
            if resp:
                if IP in resp:
                    ttl = resp.getlayer(IP).ttl
                    if ttl <= 64: 
                        os = 'Linux'
                    elif ttl > 64:
                        os = 'Windows'
                    else:
                        os = 'Unknown'
                        print('Not Found')
                    self.os_results[host_index] = os
                    print(f'\n\nTTL = {ttl} \n*{os}* Operating System is Detected \n\n')


    def __Get_Services_Running(self):
        for host_index in range (len(self.hosts)):
            print("Discovering services on host %s"  % self.hosts[host_index])
            for port_index in range (len(self.ports)):
                if self.port_results[host_index][port_index]:
                    try:
                        protocolname = 'tcp' 
                        service = getservbyport(int(self.ports[port_index]),protocolname)
                        self.ps_logger.log("Succesfully got service of port: %s" % self.ports[port_index])
                        self.service_results[host_index][port_index]=str(service)
                    except:
                        self.ps_logger.log("Failed to get the service of port: %s" % self.ports[port_index])
                        self.service_results[host_index][port_index]="Unknown"
    def search_vulnerabilities(self):
        for service in self.service_results:
            if service:
                vulnerabilities = []
            
                # Search the NVD database for vulnerabilities affecting the specified service
                url = f'https://services.nvd.nist.gov/rest/json/cves/1.1?app_prod={service}'
                r = requests.get(url)
                if r.status_code == 200:
                    data = r.json()
                    cves = data['result']['CVE_Items']
                    for cve in cves:
                        cve_id = cve['cve']['CVE_data_meta']['ID']
                        vulnerabilities.append(cve_id)
                
                print(vulnerabilities)