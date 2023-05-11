# modules
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait #For sync of threads
import sys
from io import StringIO
import logging
import ipaddress
import sys
import threading
import os
import subprocess
#import socket #IMPORTANT: import socket primul dupa from socket import | altfel nu merge port scanning!
from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOCK_DGRAM
from socket import socket
from socket import getservbyport
from socket import gethostbyaddr # for DNS checkalive
import requests
from time import sleep
#from custom_port_scanner import ThreadPing
from scapy.layers.inet import Ether, IP, TCP, ICMP, UDP
from scapy.sendrecv import send, sr1
from scapy.all import RandShort
import logger



class Port_Scanner:
    semaphore = threading.Semaphore(5) #permitem doar 5 de threaduri la rularea HALF CONNECT, comportament impredictibil altfel....
    semaphoreUDP = threading.Semaphore(100)
    ports = []
    type_of_scan = -1
    GLOBAL_TIME_OUT = 5
    hosts = []
    results = []
    checkalive_binary_results = []
    os_results=[]
    port_results = [[]]
    service_results = [[]]
    version_results = [[]]
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
        thread_arg_bool=False
        for arg in arguments_system: #### Argument for threads!
            if "-threads" in arg:
                nr_threads_str =arg[2:].split("=")[1]
                nr_threads = int(nr_threads_str)
                self.executor = ThreadPoolExecutor(nr_threads)
                print("Number of threads selected: %s" % nr_threads_str)
                thread_arg_bool=True
        if thread_arg_bool == False:
            self.executor = ThreadPoolExecutor(5)
            print("Number of threads selected default: 5")

        print("Network given:\n",ip_net)

        # get hosts
        self.hosts = list(ip_net.hosts())
        self.possible_hosts = list(ip_net.hosts())

        print("Hosts given:\n",self.hosts)
        self.os_results=[0]*len(self.hosts)
        self.checkalive_binary_results = [0]*len(self.hosts)
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
                    end = int(ports_split[1])+1
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
        self.version_results = [[0]*len(self.ports)]*len(self.hosts)

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

    def __ThreadPing(self,host,host_id):
        
        if self.checkalive_binary_results[host_id] == 0:
            try:
                self.ps_logger.log("Ping probing: %s" % host)
                command_string='ping -c 5 ' + str(host)
                tmp_res = os.popen(command_string)
                self.results[host_id]=(tmp_res.read())
                if "100% packet loss" in str(self.results[host_id]):
                    if self.checkalive_binary_results[host_id] == 1:
                        print(str(self.hosts[host_id]), "Filters ICMP pachets")
                    else:
                        print(str(self.hosts[host_id]), "is Offline")
                elif "Request timed out" in str(self.results[host_id]):
                    if self.checkalive_binary_results[host_id] == 1:
                        print(str(self.hosts[host_id]), "Filters ICMP pachets")
                    else:
                        print(str(self.hosts[host_id]), "is Offline")
                else:
                    print(str(self.hosts[host_id]), "is Online")
                    self.checkalive_binary_results[host_id]=1
            except:
                print(str(self.hosts[host_id]), "is Offline")
        else:
            print(str(self.hosts[host_id]), "is Online")

    def __DNS_CheckAlive(self,host,host_id):
            self.ps_logger.log("DNS probing: %s" % host)
            try:
                response = gethostbyaddr(host)
                # self.results[host_id] =response[0]
                self.checkalive_binary_results[host_id]=1
                self.ps_logger.log("Host with address %s has reverse DNS" % host)
                print("We found host %s to have DNS response: %s" % (host,response[0]))
            except:
                self.ps_logger.log("Host with address %s has no DNS response" % host)

    def CheckAlive(self): #WIll use DNS-checkalive and Ping_scan_hosts as well

        self.ps_logger.log("Starting DNS-Checkalive probing")
        workers = [self.executor.submit(self.__DNS_CheckAlive,str(self.hosts[i]),i) for i in range (len(self.hosts))]
        #print(workers.done()) #futures = [executor.submit(task, i) for i in range(10)]
        wait(workers)
        self.ps_logger.log("Ending DNS probing")

        self.ps_logger.log("Starting ping probing")
        workers = [self.executor.submit(self.__ThreadPing,str(self.hosts[i]),i) for i in range (len(self.hosts))]
        #print(workers.done()) #futures = [executor.submit(task, i) for i in range(10)]
        wait(workers)
        self.ps_logger.log("Ending ping probing")

        self.__Clean_Hosts_List_Of_Offline(self.hosts,self.checkalive_binary_results)
        
        self.__Get_Operating_System()

    def __Clean_Hosts_List_Of_Offline(self,hosts,checkalive_binary_results):
        for index in range(len(checkalive_binary_results)):
            if checkalive_binary_results[index]==0:
                del hosts[index]
            if not hosts:
                print("All hosts given are offline, quiting...")
                quit()
        



    def Print_Results(self):
        for host_index in range (len(self.hosts)):
            print("Open ports dicovered on host %s \nWith operating system %s:" % (self.hosts[host_index], self.os_results[host_index]))
            print("PORT\tSTATE\tSERVICE\tVERSION\t")
            for port_index in range (len(self.ports)):
                if self.port_results[host_index][port_index]:
                    print("%s\tOPEN\t%s\t%s\t" % (self.ports[port_index],self.service_results[host_index][port_index],self.version_results[host_index][port_index]))
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
            #self.semaphore.acquire()
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
            # finally:
            #     self.semaphore.release()
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
            command = "nc -z -v -u -w " + str(self.GLOBAL_TIME_OUT) + " " + str(host) + " " + port
            out = os.system(command)
            # proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            # (out, err) = proc.communicate()
            # print(out)

            if out == 0:    #=> connect succesful
                self.port_results[host_index][port_index]=port
                self.ps_logger.log("Succesfully connected to UDP port: %s" % port)
            elif out == 256:
                self.ps_logger.log("We found UDP port: %s to be closed" % port)
            else:
                self.ps_logger.log("We found UDP port: %s to be filtered" % port)
            #  nc -z -v -u -w 1 localhost 5005
            # Connection to localhost 5005 port [udp/*] succeeded!

            #     -w pt timeout ( -w 1 => timeout 1 secunda)
            # # self.semaphoreUDP.acquire()
            # self.ps_logger.log("UDP scanning port number: %s in host: %s" % (port,host))
            # ip_scan_packet = IP(dst=str(host))
            # udp_scan_packet = UDP(dport=int(self.ports[port_index]))
            # scan_packet = ip_scan_packet/udp_scan_packet
            # scan_response = sr1(scan_packet,timeout=5,verbose=0)
            # try:
            #     if scan_response is None:
            #         if len(scan_response)==0:
            #             self.ps_logger.log("We found UDP port: %s to be filtered" % port)
            #         else:
            #             self.ps_logger.log("Succesfully connected to UDP port: %s" % port)
            #             self.port_results[host_index][port_index]=port
            #     else:
            #         self.ps_logger.log("We found UDP port: %s to be closed" % port)
            # except:
            #     self.ps_logger.log("We found UDP port: %s to be closed" % port)
            #     pass
            # finally:
            #     self.semaphoreUDP.release()


        else:
            print("ERROR: type of scan undefined/wrong")
            quit()



    def __scan(self,host,host_index,ports):
        self.ps_logger.log("Start scanning: %s" % host)
        #threads_scan = list()
        #for port_index in range (len(ports)):
            #thread_scan = threading.Thread(target=self.__test_port_number, args=(host,host_index,ports[port_index],port_index,))
            #threads_scan.append(thread_scan)
            #thread_scan.start()


        workers = [self.executor.submit(self.__test_port_number, host,host_index,ports[port_index],port_index) for port_index in range (len(ports))]
        #print(workers.done()) #futures = [executor.submit(task, i) for i in range(10)]
        wait(workers)

    def Start_Port_Scanning(self):
        #threads = list()

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
        # for host_index in range (len(self.hosts)):
            
        #     thread = threading.Thread(target=self.__scan, args=(str(self.hosts[host_index]),host_index,self.ports,))
        #     threads.append(thread)
        #     thread.start()
        # for i,thread in enumerate(threads):
        #     thread.join()


        workers = [self.executor.submit(self.__scan, str(self.hosts[host_index]),host_index,self.ports) for host_index in range (len(self.hosts))]
        #print(workers.done()) #futures = [executor.submit(task, i) for i in range(10)]
        wait(workers)

        self.__Get_Services_Running()
        


    def __Get_Operating_System(self): #outdated, mai actual!!!
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
            print("Discovering services on host %s..."  % self.hosts[host_index])
            for port_index in range (len(self.ports)):
                if self.port_results[host_index][port_index]:
                    if self.type_of_scan==2: #UDP scan
                        protocolname = 'udp'
                    else:
                        protocolname='tcp'
                    try:
                        # protocolname = 'tcp' 
                        service = getservbyport(int(self.ports[port_index]),protocolname)
                        self.ps_logger.log("Succesfully got service of port: %s" % self.ports[port_index])
                        self.service_results[host_index][port_index]=str(service)
                    except:
                        self.ps_logger.log("Failed to get the service of port: %s" % self.ports[port_index])
                        self.service_results[host_index][port_index]="Unknown"
                    self.version_results[host_index][port_index]=(self.__get_service_version(self.hosts[host_index],self.ports[port_index]))
                    
    def search_vulnerabilities(self):

        for host_index in range(len(self.hosts)):
            for port_index in range(len(self.ports)):
                if self.service_results[host_index][port_index]:
                    vulnerabilities = []
                    service = self.service_results[host_index][port_index]
                    if self.version_results[host_index][port_index]:
                        version = self.version_results[host_index][port_index]
                    print("Searching vulnerabilities for %s service, version %s" % (service,version))
                    # Search the NVD database for vulnerabilities affecting the specified service
                    #url = f'https://services.nvd.nist.gov/rest/json/cves/1.1?app_prod={service}'
                    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={version}' #https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ftp
                    r = requests.get(url)
                    try:
                        if r.status_code == 200:
                            data = r.json()
                            cves = data['vulnerabilities']
                            for cve in cves:
                                cve_id = cve['cve']['id']
                                vulnerabilities.append(cve_id)
                    except:
                        vulnerabilities.append("Nothing was found...")
                    if len(vulnerabilities) == 0:
                        print("No CVE's were found for that version of the service...")
                    else:
                        print(vulnerabilities)

    def __get_service_version(self,host, port):
        # Create a socket and connect to the port
        try:
            if self.type_of_scan == 2:
                s = socket(AF_INET, SOCK_DGRAM)
                s.connect((str(host), int(port)))

                s.settimeout(10)
            else:
                s = socket(AF_INET, SOCK_STREAM)
                s.connect((str(host), int(port))) #it can fail and throws error

            # Send a request to the service and receive the response
            request = b'GET / HTTP/1.0\r\n\r\n'
            s.send(request)
            response = s.recv(1024)

            # Parse the response to get the version of the service
            version = ''
            if b'HTTP' in response:
                # HTTP response, extract version from the "Server" header
                headers = response.split(b'\r\n')
                for header in headers:
                    if header.startswith(b'Server:'):
                        version = header.split(b'/')[-1].strip().decode("utf-8").split("\n")[0] 
                        break
            else:
                # Non-HTTP response, use the response as the version
                version = response.decode("utf-8").split("\n")[0] 

            return version
        except:
            return "Unknown"
    
    def GetServices(self):
        return self.service_results
    def GetPorts(self):
        return self.port_results
    def GetHosts(self):
        return self.hosts
    def GetOnlineResults(self):
        return self.checkalive_binary_results
    

