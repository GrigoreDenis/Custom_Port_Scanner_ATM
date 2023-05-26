import yaml
import os
import requests
import re
import http.client
#import urllib.parse
class CveFinder:
    # Folder Path
    path = "cves/"
    potential_cves = []
    auxiliary_potential_cves = []
    priority_cves = []
    positive_cves = []
    def __init__(self,technology,version):
        self.tech=technology
        self.version=version
        print("Starting CVE Finder for %s version %s" % (self.tech,self.version))
        #Search everywhere for the tech in the yamls
        try:
            # iterate through all file
            folders = os.listdir('cves')
            for folder in folders:
                files = os.listdir('cves/' + folder)
                for file in files:
                    # Check whether file is in text format or not
                    if file.endswith(".yaml"):
                        filepath = 'cves/' + folder + '/' + file
                        with open(filepath, "r") as stream:
                            cve_yaml=yaml.safe_load(stream) # to avoid vulns from untrusted inputs we use safe_load
                            #print(cve_yaml)
                            cve_name = cve_yaml['info']['name']
                            cve_info = cve_yaml['info']
                            if cve_name.find(self.tech)!= -1:
                                #print("Found tech %s inside %s" % (self.tech,cve_name))
                                self.__add_potential_cve_file(filepath)
                                if cve_name.find(self.version)!= -1:
                                    #print("Found version %s inside %s" % (self.version,cve_name))
                                    self.__Increment_Priority(filepath)
                            for cve_obj in cve_info:
                                if cve_obj != "remediation":
                                    cve_obj_list = cve_info[cve_obj]
                                    if isinstance(cve_obj_list, list):  #CASE IF IT IS A LIST
                                        for cve_obj_list_index in cve_obj_list:
                                            if cve_obj_list_index.find(self.tech)!= -1:
                                                #print("Found tech %s inside %s" % (self.tech,cve_obj_list_index))
                                                self.__add_potential_cve_file(filepath)
                                                if cve_obj_list_index.find(self.version)!= -1:
                                                    #print("Found version %s inside %s" % (self.version,cve_obj_list_index))
                                                    self.__Increment_Priority(filepath)
                                    else: #CASE IF IT IS NOT A LIST
                                        try:
                                            if cve_obj_list.find(self.tech)!= -1:
                                                    #print("Found tech %s inside %s" % (self.tech,cve_obj_list))
                                                    self.__add_potential_cve_file(filepath)
                                                    if cve_obj_list.find(self.version)!= -1:
                                                        #print("Found version %s inside %s" % (self.version,cve_obj_list))
                                                        self.__Increment_Priority(filepath)
                                                        
                                        except:
                                            #print("Error for cve_obj_list = %s" % cve_obj_list)
                                            pass
                                #Find tech and/or version inside info-name in yaml using python find() method => -1 => not found

        except yaml.YAMLError as exc:
            print(exc)
            print("ERROR!")
    def __add_potential_cve_file(self,file):
        self.auxiliary_potential_cves.append(file)
        for word in self.auxiliary_potential_cves:
            if word not in self.potential_cves:
                self.potential_cves.append(word)
                self.priority_cves.append(1)
    def __Increment_Priority(self,file):
        for index in range(len(self.potential_cves)):
            if self.potential_cves[index] == file:
                self.priority_cves[index] += 1 #Increment the "priority"
                break
    def Print_Potential_Cves(self): # make more pretty
        max_priority = max(self.priority_cves)
        while max_priority > 0:
            for filepath_index in range(len(self.potential_cves)):
                if self.priority_cves[filepath_index] == max_priority :
                    with open(self.potential_cves[filepath_index], "r") as stream:
                        cve_yaml=yaml.safe_load(stream) # to avoid vulns from untrusted inputs we use safe_load
                        cve_id = cve_yaml['id']
                        print(cve_id + ":\t" + cve_yaml['info']['tags'])
                        print("PROPRITY: ", self.priority_cves[filepath_index])
            max_priority -=1
    def Confirm_Vulnerabilities(self,network,hostname,port,url):#,ports,services):
        self.ip=network
        self.port = port
        #using the requests from the yaml files and then comparing the output with the yaml file output to confirm
        #make 3 lists of vulns: confirmed valid, confirmed invalid, unconfirmed
        network = str(network)

        host = hostname
        max_priority = max(self.priority_cves)
        while max_priority > 1:
            for filepath_index in range(len(self.potential_cves)):
                if self.priority_cves[filepath_index] == max_priority :
                    with open(self.potential_cves[filepath_index], "r") as stream:
                    
                        try: # use http.client !
                            
                            cve_yaml=yaml.safe_load(stream) # to avoid vulns from untrusted inputs we use safe_load
                            request = cve_yaml['requests'][0]
                            url = "http://" + network + ":" + port
                            try:
                                #matchers_condition = request['matchers-condition']
                                matchers = (request['matchers'],request['matchers-condition'])
                            except:
                                matchers = request['matchers'] 
                            try:
                                method = request['method']
                                path = request['path']
                                print(method)
                                print(path)
                                if isinstance(path, list):
                                    for payload_raw in path:
                                        payload = self.Replace_arguments(payload_raw,url,host,self.potential_cves[filepath_index])
                                        
                                        url += payload

                                        if method == "GET":
                                            
                                            #headers = { "Host" : "Localhost"}
                                            response = requests.get(url)#,headers=headers)
                                            print("From %s we got response:\n%s\n\n\n\n" % (self.potential_cves[filepath_index],response.text))
                                            
                                        elif method == "POST":
                                            headers = { "Host" : "localhost"}
                                            response = requests.post(url,headers=headers)
                                            print("From %s we got response:\n%s\n\n\n\n" % (self.potential_cves[filepath_index],response.text))
                                        else:
                                            print("Error, method of request not supported for this one...")

                                #Matchers:
                                #FOR RCE (Remote Code Execution, make matchers ("echo {{cmd}}")) something default
                                #FOR LFI Usually "root:.*:0:0:"




                            except:
                                raw = request['raw']                                

                                for raw_element in raw:


                                    url = "http://" + network + ":" + port
                                    shorturl = network + ":" + port



                                    if re.search('^GET',raw_element):
                                        payload_raw = raw_element[4:]

                                        payload = self.Replace_arguments(payload_raw,url,host)#,self.potential_cves[filepath_index])

                                        headers = payload.split(" ",1)[1].split("\n",1)[1]
                                        payload = payload.split(" ")[0]
                                        headers = self.__Get_Headers_Dict(headers)
                                        response = self.Deliver_Get_Payload(shorturl,payload,headers)

                                        bool_confirm = self.Match_Response(response,matchers)

                                        if bool_confirm == True:
                                            print("From %s we confirmed CVE!\n\n" % self.potential_cves[filepath_index])
                                            print("\t->PAYLOAD{GET}: %s\n" % payload)
                                            print("RESPONSE: %s" % response)
                                            self.positive_cves.append(self.potential_cves[filepath_index])
                                        else:
                                            print("From %s we could NOT confirm CVE!\n\n\n" % self.potential_cves[filepath_index])
                                        
                                    elif re.search('^POST',raw_element):
                                        payload_raw = raw_element[5:]
                                        payload = self.Replace_arguments(payload_raw,url,host)#,self.potential_cves[filepath_index])
                                        
                                        headers = payload.split(" ",1)[1].split("\n",1)[1]
                                        payload = payload.split(" ")[0]
                                        headers_new = self.__Get_Headers_Dict(headers) #AFTER HEADERS, WE GET DATA
                                        data_new = self.__Get_Data_Dict(headers)
                                        response = self.Deliver_Post_Payload(shorturl,payload,headers_new,data_new)
                                        bool_confirm = self.Match_Response(response,matchers)

                                        if bool_confirm == True:
                                            print("From %s we confirmed CVE!\n\n" % self.potential_cves[filepath_index])
                                            print("\t->PAYLOAD{POST}: %s\n" % payload)
                                            print("RESPONSE: %s" % response)
                                            self.positive_cves.append(self.potential_cves[filepath_index])
                                        else:
                                            print("From %s we could NOT confirm CVE!\n\n\n" % self.potential_cves[filepath_index])
                                    else:
                                        print("Error, method of request not supported for this one...")

                                #use methods requests.get and requests.post
                                

                            print("PROPRITY: ", self.priority_cves[filepath_index])
                            print("\n\n\n")

                        except Exception as ex:
                            print("Error for file: %s" % self.potential_cves[filepath_index])
                            print(ex)
                            print("PROPRITY: ", self.priority_cves[filepath_index])
                            print("\n\n\n")
            max_priority -=1

    def Replace_arguments(self,payload,baseurl,hostname):
        print(hostname)
        if "{{BaseURL}}" in payload:
            payload = payload.replace("{{BaseURL}}", baseurl)
        if "{{Hostname}}" in payload:
            payload = payload.replace("{{Hostname}}", hostname)
        if "{{cmd}}" in payload:
            #payload = payload.replace("{{cmd}}","echo " + cve_name) # or..
            payload = payload.replace("{{cmd}}","cat /etc/passwd")
        if "{{Command}}" in payload:
            payload = payload.replace("{{Command}}","cat /etc/passwd")
        return payload
    
    def Deliver_Get_Payload(self,shorturl,payload,headers): #ADD HTTPS FUNCTIONALITY
        conn = http.client.HTTPConnection(shorturl) 

        conn.request("GET", payload,headers=headers)

        res = conn.getresponse()
        data = res.read()

        return data.decode("utf-8")
    
    def Deliver_Post_Payload(self,shorturl,payload,headers,data): #ADD HTTPS FUNCTIONALITY
        conn = http.client.HTTPConnection(shorturl)

        conn.request("POST", payload,headers=headers,body=data)
        print(conn)
        res = conn.getresponse()
        data = res.read()

        return data.decode("utf-8")
    
    def Match_Response(self,response,matchers): #matchers -> list
        matcher_count = 0
        for matcher in matchers[0]:
            #print(matcher)
            if matcher["type"] == "regex": #if regex
                regex = matcher['regex'][0]
                regex_res = re.findall(regex, response)
                if regex_res:
                    matcher_count +=1
        if matcher_count != 0:
            return True
        else:
            return False
    def Print_Positive_CVEs(self):
        if self.positive_cves:
            for cve in self.positive_cves:
                #cve_nice = cve.split("/")[2].split(".")[0]
                print("The following host: %s\nTechnology: %s\nVersion: %s\nPort: %s\nVulnerable to %s\n" % (self.ip,self.tech,self.version,self.port,cve))
        else:
            print("The following host: %s\nTechnology: %s\nVersion: %s\nPort: %s\nNOT vulnerable to any of our CVE's\n" % (self.ip,self.tech,self.version,self.port,cve))
    def __Get_Headers_Dict(self,headers):
        headers_dict = {}
        headers_list=headers.split("\n")
        pause_found = False
        for header in headers_list:
            if header and not pause_found:
                name = header.split(":",1)[0]
                desc = header.split(":",1)[1].split(" ",1)[1]
                if name in headers_dict.keys():
                    headers_dict[name]= desc
                else:
                    headers_dict[name] = ""
                    headers_dict[name] = desc
            else:
                pause_found = True
                #break?
        return headers_dict
    
    def __Get_Data_Dict(self,headers):
        #We are looking for a pause before DATA
        empty = ""
        #data_dict = {}
        data_list=headers.split("\n")
        pause_found= False
        for data in data_list:
            if data and pause_found:
                return data
                # name = data.split(":",1)[0]
                # desc = data.split(":",1)[1].split(" ",1)[1]
                # if name in data_dict.keys():
                #     data[name]= desc
                # else:
                #     data[name] = ""
                #     data[name] = desc
            else:
                if data:
                    continue
                else:
                    pause_found = True
        return empty