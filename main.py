import os
from custom_port_scanner import Port_Scanner
from FingerPrinter.FingerPrinter import FingerPrinter
from Enumerator import Enumerator
from logger import logger
import sys
import sys
from CveFinder import CveFinder
if os.geteuid() != 0:       #Checks for root
    exit("You need to have root privileges to run this framework.\nPlease try again, this time using 'sudo'. Exiting.")

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
    print("Use -threads=### to define the number of threads used, default = 5, examples: -threads=100")
    quit()

if "-logs" in sys.argv:  # 1 = log stuff, 0 = don't log
    log_level=1
else:
    log_level=0

for argv_t in sys.argv:
    if "-timeout=" in argv_t:
        GLOBAL_TIME_OUT = int(argv_t.split("=")[1])
        print("Setting global timeout to: %d" % GLOBAL_TIME_OUT)

main_logger = logger(log_level)

scanner = Port_Scanner(network,sys.argv) # seachers for an argument to include a scan type -tcs | -ths | -udp | -sth

scanner.Get_Port_Arguments(sys.argv)

scanner.CheckAlive()

scanner.Start_Port_Scanning()

scanner.Print_Results()

#scanner.search_vulnerabilities()

#Extract service and port results to be used by FingerPrinter & CveFinder

hosts = scanner.GetHosts()
ports = scanner.GetPorts()
online_hosts = scanner.GetOnlineResults()
services = scanner.GetServices()

# for host_index in range(len(hosts)):
#     for port_index in range(len(hosts)): #TODO -> lista http/ ia din srv | NR 13|17 in TODO.txt
print(hosts)
for host in hosts:
    enumerator = Enumerator(host)
    enumerator._WhoIs()


fingerprinter = FingerPrinter(hosts,ports,online_hosts,services,sys.argv)

cve_ports = fingerprinter.GetPorts()
cve_hosts = fingerprinter.GetHosts()
cve_hostnames = fingerprinter.GetHostnames()
cve_techs = fingerprinter.GetTechs()
cve_versions = fingerprinter.GetVersions()
cve_len = fingerprinter.GetLen()
cve_urls = fingerprinter.GetURLs()


# for index in range(cve_len): #DIRBUSTER DUPA FINGERPRINTER, DOAR PE HTTP
Enumerator.DirBuster(cve_urls) #https://github.com/digination/dirbuster-ng/blob/master/wordlists/common.txt 
                                                            #For testing purposes

for index in range(cve_len):
    Cve_Finder = CveFinder(cve_techs[index],cve_versions[index])
    #Cve_Finder.Print_Potential_Cves()
    Cve_Finder.Confirm_Vulnerabilities(cve_hosts[index],cve_hostnames[index],cve_ports[index],cve_urls[index])
    Cve_Finder.Print_Positive_CVEs() #print if there are any



    # def GetServices(self):
    #     return self.service_results
    # def GetPorts(self):
    #     return self.port_results
    # def GetHosts(self):
    #     return self.hosts
    # def GetOnlineResults(self):
    #     return self.checkalive_binary_results