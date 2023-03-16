import yaml
import os
class CveFinder:
    # Folder Path
    path = "cves/"
    potential_cves = []
    auxiliary_potential_cves = []
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
                                print("Found tech %s inside %s" % (self.tech,cve_name))
                                self.__add_potential_cve_file(filepath)
                                if cve_name.find(self.version)!= -1:
                                    print("Found version %s inside %s" % (self.version,cve_name))
                            for cve_obj in cve_info:
                                cve_obj_list = cve_info[cve_obj]
                                if isinstance(cve_obj_list, list):  #CASE IF IT IS A LIST
                                    for cve_obj_list_index in cve_obj_list:
                                        if cve_obj_list_index.find(self.tech)!= -1:
                                            print("Found tech %s inside %s" % (self.tech,cve_obj_list_index))
                                            self.__add_potential_cve_file(filepath)
                                            if cve_obj_list_index.find(self.version)!= -1:
                                                print("Found version %s inside %s" % (self.version,cve_obj_list_index))
                                else: #CASE IF IT IS NOT A LIST
                                    try:
                                        if cve_obj_list.find(self.tech)!= -1:
                                                print("Found tech %s inside %s" % (self.tech,cve_obj_list))
                                                self.__add_potential_cve_file(filepath)
                                                if cve_obj_list.find(self.version)!= -1:
                                                    print("Found version %s inside %s" % (self.version,cve_obj_list))
                                                    
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
    def Print_Potential_Cves(self): # make more pretty
        for filepath in self.potential_cves:
            with open(filepath, "r") as stream:
                cve_yaml=yaml.safe_load(stream) # to avoid vulns from untrusted inputs we use safe_load
                cve_id = cve_yaml['id']
                print(cve_id + ":\t" + cve_yaml['info']['tags'])
    def Confirm_Vulnerabilities(self,network):
        #using the requests from the yaml files and then comparing the output with the yaml file output to confirm
        #make 3 lists of vulns: confirmed valid, confirmed invalid, unconfirmed
        
# requests:
#   - method: GET
#     path:
#       - "{{BaseURL}}/Dialog/FileDialog.aspx?ed=foooooooooooooo%27);});});javascript:alert('document.domain');//g"

#     matchers-condition: and
#     matchers:
#       - type: word
#         part: body
#         words:
#           - "javascript:alert('document.domain')"
#           - "File Browser"
#         condition: and

#       - type: word
#         part: header
#         words:
#           - "text/html"

#       - type: status
#         status:
#           - 200
        for filepath in self.potential_cves:
            with open(filepath, "r") as stream:
                cve_yaml=yaml.safe_load(stream) # to avoid vulns from untrusted inputs we use safe_load
                request = cve_yaml['requests'][0]
                print(request)
                method = request['method']
                path = request['path']
                matchers_condition = request['matchers-condition']
                matchers = request['matchers'] 
                #[{'type': 'word', 'part': 'body', 'words': ["javascript:alert('document.domain')", 'File Browser'], 'condition': 'and'}, 
                # {'type': 'word', 'part': 'header', 'words': ['text/html']}, {'type': 'status', 'status': [200]}]
                print(matchers)
                # type = request['type']
                # print(type)


Cve_Finder = CveFinder('nginx','1.18.0') # was mojoPortal
Cve_Finder.Print_Potential_Cves()
Cve_Finder.Confirm_Vulnerabilities('10.10.11.189')


