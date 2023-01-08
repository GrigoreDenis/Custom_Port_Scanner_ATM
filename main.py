from custom_port_scanner import Port_Scanner
from logger import logger
import sys
import sys
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

if "-logs" in sys.argv:  # 1 = log stuff, 0 = don't log
    log_level=1
else:
    log_level=0

for port_argument in sys.argv:
    if "-timeout=" in port_argument:
        GLOBAL_TIME_OUT = int(port_argument.split("=")[1])
        print("Setting global timeout to: %d" % GLOBAL_TIME_OUT)

main_logger = logger(log_level)

scanner = Port_Scanner(network,sys.argv) # seachers for an argument to include a scan type -tcs | -ths | -udp | -sth

scanner.Get_Port_Arguments(sys.argv)

scanner.Ping_Scan_Hosts()

#scanner.Use_Default_1000_Ports()

scanner.Start_Port_Scanning()

scanner.Print_Results()

scanner.search_vulnerabilities()