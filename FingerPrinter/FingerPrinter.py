import ipaddress
import subprocess
import requests
import http.client
import re
from socket import gethostbyaddr # for DNS checkalive
def Deliver_Get_Request(shorturl):
    response = requests.get(shorturl)
    #print(response.status_code)
    #return data.decode("utf-8")
    return response

def Deliver_Head_Request(shorturl):
    response = requests.head(shorturl)
    #print(response.headers)
    #return data.decode("utf-8")
    return response

def Build_Url(prefix,target_ip_port):
    url = prefix+target_ip_port
    return str(url)
    
def Check_http_or_https(target_ip_port):

    #Incearca HTTP:
    check_url = Build_Url("http://",target_ip_port) 
    try:
        response = requests.head(check_url)
        status = str(response.status_code)
        regex_match_2XX = re.search("20[0-9]",status)
        if regex_match_2XX:
            print("%s: Got success code:%s" % (check_url,status))
            return check_url
        regex_match_3XX = re.search("30[0-9]",status)
        if regex_match_3XX:
            print("%s: Got redirect code:%s" % (check_url,status))
    except Exception as e:
        print("Exception in Fingerprinter for http check:")
        print(e)
        print("\n\n\n")
        


    #Incearca HTTPS:
    check_url = Build_Url("https://",target_ip_port) 
    try:
        response = requests.head(check_url)
        status = str(response.status_code)
        regex_match_2XX = re.search("2.[0-9]",status)
        if regex_match_2XX:
            print("%s: Got success code:%s" % (check_url,status))
            return check_url
        regex_match_3XX = re.search("30[0-9]",status)
        if regex_match_3XX:
            print("%s: Got redirect code:%s" % (check_url,status))
    except Exception as e:
        print("Exception in Fingerprinter for https check:")
        print(e)
        print("\n\n\n")


    # Check(shorturl_wrong) # 3XX -> redirect => trebuie https in loc de http
    # Check(shorturl_right) # 2XX -> success

class FingerPrinter:
    To_be_confirmed_len = 0
    hostname = []
    tech =[]
    version = []
    ports = []
    hosts = []
    shorturls = []
    def __validate_input(self,network_input):
        try:
            ipaddress.ip_address(network_input)
        except:
            print("You introduced an eronated network address, only IPv4 and IPv6")
            exit

    def __init__(self, hosts,ports,online_hosts,services, arguments_system):
        print("Running Fingerprinter script")

        for host_index in range(len(hosts)):
            if online_hosts[host_index] == 1:
                self.__validate_input(hosts[host_index]) # sanitize against command injection (we'll use os.system)
                self.ip_address = hosts[host_index]
                
                for port_index in range(len(ports[host_index])):
                    if services[host_index][port_index]: # REPAIR THIS



                        self.target_ip_port = str(self.ip_address) + ":" + str(ports[host_index][port_index])
                        #print(self.target_ip_port) # USE ONLY THOSE WITH SERVICE ON THEM!!!

                        
                        #CHECK IF PORT IS HTTP BY PROBING USING HEAD/GET request 
                        #httpcheck_url = Check_http_or_https(self.target_ip_port)
                        httpcheck_url = "http://" + self.target_ip_port

                        
                        try:
                            response = Deliver_Get_Request(httpcheck_url)
                        except:
                            try:
                                response = Deliver_Head_Request(httpcheck_url)
                            except:
                                print("Following url is NOT a valid HTTP service %s\n\t Got no response\n" % httpcheck_url)
                                continue
                        if response:
                            print("Following url is a valid HTTP service %s\n\t Got response status: %s\n" % (httpcheck_url,response.status_code) )


                        httpcheck_url = Check_http_or_https(self.target_ip_port)

                        command = "FingerPrinter/WhatWeb-master/whatweb -v -a 3 " + httpcheck_url
                        #os.system(command)
                        proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
                        (out, err) = proc.communicate()

                        if "HTTPServer" in out.decode('ascii'):
                            #self.technology_found=out.decode('ascii').split("HTTPServer: ")[0].split("String")[1].split("\n")[0].split("(")[0].split(":")[1] #OLD
                            self.technology_found=out.decode('ascii').split("HTTPServer")[1].split("\n")[0].encode('utf-8').split('[\x1b[1m\x1b[36m'.encode('utf-8'))[1].split(' '.encode('utf-8'))[0].decode('ascii')
                            try:
                                self.technology_found = self.technology_found.split("]")[0]
                            except:
                                pass
                        elif "Server" in out.decode('ascii'):
                            #self.technology_found=out.decode('ascii').split("Server: ")[0].split("String")[1].split("\n")[0].split("(")[0].split(":")[1] #OLD
                            self.technology_found=out.decode('ascii').split("Server")[1].split("\n")[0].encode('utf-8').split('[\x1b[1m\x1b[36m'.encode('utf-8'))[1].split(' '.encode('utf-8'))[0].decode('ascii')
                            try:
                                self.technology_found = self.technology_found.split("]")[0]
                            except:
                                pass
                        try:
                            print("Technology used given by WhatWeb output for port %s : %s\n\n" % (ports[host_index][port_index],self.technology_found))
                            self.tech.append(self.technology_found.split("/")[0])
                            self.version.append(self.technology_found.split("/")[1])
                            self.ports.append(ports[host_index][port_index])
                            self.hosts.append(hosts[host_index])
                            self.shorturls.append(httpcheck_url)
                            self.To_be_confirmed_len +=1
                            try:
                                self.hostname.append(gethostbyaddr(str(self.ip_address))[0]) #Get only the host, gethostbyaddr returns tuple
                            except:
                                self.hostname.append("Unknown")
                        except:
                            print("Port: %s has no technology that WhatWeb can indentify" % str(ports[host_index][port_index]))
                            pass

                
    def GetTechs(self):
        return self.tech #LIST
    def GetVersions(self):
        return self.version #LIST
    def GetHostnames(self):
        return self.hostname #LIST
    def GetPorts(self):
        return self.ports #LIST
    def GetHosts(self):
        return self.hosts #LIST
    def GetLen(self):
        return self.To_be_confirmed_len
    def GetURLs(self):
        return self.shorturls
    
    
#String       : \x1b[1m\x1b[36mnginx/1.18.0\x1b[0m (from server string) to be parsed example nginx/1.18.0

# [ nginx ]
#         Nginx (Engine-X) is a free, open-source, high-performance 
#         HTTP server and reverse proxy, as well as an IMAP/POP3 
#         proxy server. 

#         Version      : 1.18.0
#         Website     : http://nginx.net/

#test done on sudo python3 main.py 10.10.11.186 -tcs -threads=200 (hack the box vpn| MetaTwo machine)
