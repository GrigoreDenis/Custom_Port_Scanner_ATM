import os
if os.geteuid() != 0:       #Checks for root
    exit("You need to have root privileges to run this framework.\nPlease try again, this time using 'sudo'. Exiting.")

import sys
 
# setting path
sys.path.append('../')
 
# importing
import textile
from flask import Flask, render_template, redirect, url_for, request, session, current_app, g
from flask import copy_current_request_context
from threading import Thread, Event
from custom_port_scanner import Port_Scanner
from FingerPrinter.FingerPrinter import FingerPrinter
from Enumerator import Enumerator
from CveFinder import CveFinder
import sqlite3
import logging
from datetime import datetime
from _database_init import _database_init
import subprocess
import json
# Configure the logging
logging.basicConfig(filename='web_activity.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

_database_init._init_database() # we create our database, if all tables exist already -> we ignore

#global_report_id = 0

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SERVER_NAME'] = 'localhost:5000'  
app.config['APPLICATION_ROOT'] = '/'  
app.config['PREFERRED_URL_SCHEME'] = 'http'
app.config['TIMEOUT'] = 60  # Set the timeout to 30 second
event = Event()

def Add_html_color(color_hex_code,text): #give with "#ffffff"
    html_color = '''<span style="color:'''+color_hex_code+''';">'''+text+'''</span>'''
    return html_color
def get_color(value):
    # Calculate the color based on the value
    red = int((value/10) * 255)
    green = int((1 - value/10) * 255)
    blue = 0
    
    # Format the RGB values as a hexadecimal color code
    color_code = "#{:02X}{:02X}{:02X}".format(red, green, blue)
    return color_code

def execute_pentest(network,type_of_scan,thread_range,global_timeout,port_range):
    # Perform long-running task here

    with app.app_context():
        logging.info(network)
        logging.info(type_of_scan)
        logging.info(thread_range)
        logging.info(global_timeout)
        logging.info(port_range)
        if port_range:
            Port_scanner_input = network + " -" + type_of_scan + " -threads=" + thread_range  + " -p" + port_range + " -timeout=" + global_timeout
        else:
            Port_scanner_input = network + " -" + type_of_scan + " -threads=" + thread_range + " -timeout=" + global_timeout
        Port_scanner_input_arguments = Port_scanner_input.split(" ")
        scanner = Port_Scanner(network,Port_scanner_input_arguments) # seachers for an argument to include a scan type -tcs | -ths | -udp | -sth
        # sudo python3 main.py 127.0.0.1 -tcs -threads=200 -p1-9000

        scanner.Get_Port_Arguments(Port_scanner_input_arguments)
        scanner.CheckAlive()
        scanner.Start_Port_Scanning()

        #scanner.Print_Results() 
        #log them and insert them into SQLite

        #Extract service and port results to be used by FingerPrinter & CveFinder

        hosts = scanner.GetHosts()
        ports = scanner.GetPorts()
        online_hosts = scanner.GetOnlineResults()
        services = scanner.GetServices()
        versions = scanner.GetVersions()
        dns_results = scanner.GetDNSResponses()
        os_results = scanner.GetOSResults()
        if scanner.AnyOnline_Boolean == False:
            print("No online hosts found")
            return render_template('Main-Framework.html')

        fingerprinter = FingerPrinter(hosts,ports,online_hosts,services)#,sys.argv)

        cve_ports = fingerprinter.GetPorts()
        cve_hosts = fingerprinter.GetHosts()
        cve_hostnames = fingerprinter.GetHostnames()
        cve_techs = fingerprinter.GetTechs()
        cve_versions = fingerprinter.GetVersions()
        cve_len = fingerprinter.GetLen()
        cve_urls = fingerprinter.GetURLs()

        for index in range(cve_len):
            Cve_Finder = CveFinder(cve_techs[index],cve_versions[index])
            Cve_Finder.Confirm_Vulnerabilities(cve_hosts[index],cve_hostnames[index],cve_ports[index],cve_urls[index])

        # Get the current timestamp
        current_time = datetime.now()

        conn = sqlite3.connect('pentestframeworkdb.db')
        cursor = conn.cursor()

        # Insert a single row of values into a table # reports, hosts, ports, fingerprints, cves
        cursor.execute("INSERT INTO reports (network, timestamp) VALUES (?, ?)", (network, current_time))

        # Insert multiple rows of values into a table # hosts and ports...
        # Get the id of the newly inserted row
        report_id = cursor.lastrowid
        host_ids = [0]*len(hosts)
        # Use the id as a foreign key for the second insert
        for host_index in range(len(hosts)):
            if online_hosts[host_index] == 1:
                values = (report_id, str(hosts[host_index]), dns_results[host_index],os_results[host_index])
                cursor.execute("INSERT INTO hosts (id_report, ip, hostname, os) VALUES (?, ?, ?, ?)", values)
                host_ids[host_index] = cursor.lastrowid
                for port_index in range(len(ports[host_index])):
                    if ports[host_index][port_index]: #means it's open
                        values_ports = (host_ids[host_index],ports[host_index][port_index],1,services[host_index][port_index],versions[host_index][port_index])
                        cursor.execute("INSERT INTO ports (id_host, port_number, status, service, version) VALUES (?, ?, ?, ?, ?)", values_ports)
        
        fingerprinter_ids = [0]*cve_len
        for fingerprinter_index in range(cve_len):
            values_fingerprinter = (report_id,cve_urls[fingerprinter_index],cve_techs[fingerprinter_index],cve_versions[fingerprinter_index],cve_ports[fingerprinter_index],str(cve_hosts[fingerprinter_index]))
            cursor.execute("INSERT INTO fingerprints (id_report, url, technology, version, port, host) VALUES (?, ?, ?, ?, ?, ?)", values_fingerprinter)
            fingerprinter_ids[fingerprinter_index] = cursor.lastrowid
            if Cve_Finder.Check_For_Positive_CVEs(cve_urls[fingerprinter_index]) == 1:
                List_CVE_cvss_score = Cve_Finder.Get_List_CVE_cvss_score(cve_urls[fingerprinter_index])
                List_CVE_description = Cve_Finder.Get_List_CVE_description(cve_urls[fingerprinter_index])
                List_CVE_id = Cve_Finder.Get_List_CVE_id(cve_urls[fingerprinter_index])
                List_CVE_name = Cve_Finder.Get_List_CVE_name(cve_urls[fingerprinter_index])
                List_CVE_payload = Cve_Finder.Get_List_CVE_payload(cve_urls[fingerprinter_index])
                List_CVE_response = Cve_Finder.Get_List_CVE_response(cve_urls[fingerprinter_index])
                List_CVE_severity = Cve_Finder.Get_List_CVE_severity(cve_urls[fingerprinter_index])
                List_len=len(List_CVE_id)
                for cve_index in range(List_len):
                    values_cve = (fingerprinter_ids[fingerprinter_index],List_CVE_name[cve_index],List_CVE_id[cve_index],List_CVE_cvss_score[cve_index],List_CVE_response[cve_index],List_CVE_payload[cve_index],List_CVE_description[cve_index],List_CVE_severity[cve_index])
                    cursor.execute("INSERT INTO cves (id_fingerprint, cve_name, cve_id, cvss_score, response, payload, description, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", values_cve)

        # Commit the changes
        conn.commit()

        # Close the connection
        conn.close()

        #session['report_id'] = report_id
        #global_report_id = report_id
    # Update the app context to access the result in the template
    # with app.app_context():
        app.pentest_report_id = report_id

    # Redirect to the 'result' route after the long function completes
        print("Redirecting")
        # Main_Framework_Expanded()
        # return redirect("/Main_Framework_Expanded", code=302)
        # Thread is finished, signal the event
        event.set()




@app.route('/')
def main(): # Initialization of main
    logging.info('Web interface initialized')
    return render_template('Main-Framework.html')#,checkalive_output_arg = '', port_scanner_output_arg='', fingerpinter_output_arg='',cve_finder_output_arg='')



@app.route('/start_pentest', methods=['POST']) #Extended form of main
def start_pentest():
    logging.info('Starting main framework')
    network = request.form.get('network')
    type_of_scan = request.form.get('type_of_scan')
    thread_range = request.form.get('thread_range')
    global_timeout = request.form.get('global_timeout')
    port_range = request.form.get('port_range')
    #Call upon the customportscaner, fingerpinter, cvefinder class and get output from them

    #execute_pentest(network,type_of_scan,thread_range,global_timeout,port_range)

    # Start the long function in the background
    thread = Thread(target=execute_pentest,args=(network,type_of_scan,thread_range,global_timeout,port_range))
    thread.start()

    #return render_template('Main-Framework-Expanded.html', port_scanner_output='[[data]]', fingerpinter_output='',cve_finder_output='')

    print("Redirecting...")
    # Perform the redirect
    #return redirect(url_for('Main_Framework_Expanded', value=session['report_id']), code=307) # code 307 forces redirect to keep same method, this case: POST method
    #return render_template('Main-Framework.html')#,checkalive_output_arg = '', port_scanner_output_arg='', fingerpinter_output_arg='',cve_finder_output_arg='')
    #return render_template('Main-Framework-Expanded.html',checkalive_output_arg = 'test', port_scanner_output_arg='test', fingerpinter_output_arg='test',cve_finder_output_arg='test')
    return Main_Framework_Expanded()

#,checkalive_output_arg = '', port_scanner_output_arg = '', fingerpinter_output_arg = '', cve_finder_output_arg = '')

@app.route('/Main_Framework_Expanded')
def Main_Framework_Expanded():
    # Access the value from the query parameter or session variable
    #report_id = request.args.get('report_id') or session.get('report_id')
    event.wait()# Wait for the event to be set by the secondary thread
    report_id = app.pentest_report_id
    #report_id = session.pop('report_id', None)
    #report_id = global_report_id
    print("REPORT_ID=%s" % str(report_id))
    

    conn = sqlite3.connect('pentestframeworkdb.db')
    cursor = conn.cursor()
    # Select rows where id is the given value
    cursor.execute("SELECT * FROM reports WHERE id = ?", (report_id,))

    # Fetch the selected rows
    report_rows = cursor.fetchall()
    network = ''
    timestamp = ''
    host_rows = []
    fingerprinter_rows = []
    # Print the selected rows
    for row in report_rows:
        #print(row)
        network = row[1]
        timestamp = row[2]
        cursor.execute("SELECT * FROM hosts WHERE id_report = ?", (report_id,))
        host_rows = cursor.fetchall()
        # for host_row in host_rows:
        #     #print(host_row)
        #     host_id = host_row[0]
        #     cursor.execute("SELECT * FROM ports WHERE id_host = ?", (host_id,))
        #     port_rows = cursor.fetchall()
        #     for port_row in port_rows:
        #         print(port_row)
        cursor.execute("SELECT * FROM fingerprints WHERE id_report = ?", (report_id,))
        fingerprinter_rows = cursor.fetchall()
        # for fingerprinter_row in fingerprinter_rows:
        #     print(fingerprinter_row)
        #     fingerprinter_id = fingerprinter_row[0]
        #     cursor.execute("SELECT * FROM cves WHERE id_fingerprint = ?", (fingerprinter_id,))
        #     cve_rows = cursor.fetchall()
        #     for cve_row in cve_rows:
        #         print(cve_row)
    ###OUTPUTS::
    if len(host_rows) != 0:
        checkalive_output = '''<span style="color: #2cccc4;">Network given: <span class="u-text-palette-3-base">'''+ network +'''</span>\nTimestamp: <span style="color: #ffffff;">'''+ timestamp +'''</span>\nHosts given:\n\n'''
    else:
        checkalive_output = '''<span style="color: #2cccc4;">No network was found online! </span>'''
    for host_row in host_rows:
        checkalive_output += "* " + Add_html_color('#f1c50e',host_row[2]) + "\n"
    for host_row in host_rows:
        if host_row[3]:
            checkalive_output += '''\nWe found host ''' + Add_html_color('#f1c50e',host_row[2]) + ''' to have DNS response: ''' + Add_html_color('#f1c50e',host_row[3]) + '''\n'''
            checkalive_output += Add_html_color('#f1c50e',host_row[2]) + ''' is Online\n'''
            if host_row[4] == '0' or host_row[4] == "Unknown":
                os=Add_html_color('#ff0000',"Unknown")
            else:
                os=Add_html_color('#00ff00',host_row[4])
            checkalive_output += '''With operating system: ''' + os
    if len(host_rows) != 0:
        checkalive_output +='''</span>'''
    


    port_scanner_output = ""
    for host_row in host_rows:
        host_id = host_row[0]
        port_scanner_output += '''<span class="u-text-palette-3-base">''' + host_row[2] + ''' DNS ''' + host_row[3] + '''</span>\n\n<span class="u-text-custom-color-4">PORT STATE SERVICE VERSION\n'''
        cursor.execute("SELECT * FROM ports WHERE id_host = ?", (host_id,))
        port_rows = cursor.fetchall()
        last_port = port_rows[-1]
        for port_row in port_rows:
            port_scanner_output += str(port_row[2]) + ''' OPEN ''' + port_row[4] + ''' ''' + port_row[5] + '''\n'''
            if port_row == last_port:
                port_scanner_output += '''</span>'''



    fingerpinter_output = ""
    cve_finder_output = ""
    for fingerprinter_row in fingerprinter_rows:
            #print(fingerprinter_row)
            fingerprinter_id = fingerprinter_row[0]
            fingerpinter_output += '''Following url is a valid HTTP service ''' + Add_html_color('#69bdff',fingerprinter_row[2]) + '''\nGot response status: '''+Add_html_color('#00ff00','200')+'''\n\nTechnology used given by WhatWeb output for port '''+ Add_html_color('#04ff00',fingerprinter_row[5]) + ''' : <span class="u-text-custom-color-5">''' + fingerprinter_row[3] + '''/''' + fingerprinter_row[4] + '''</span>\n\n\n'''
            cursor.execute("SELECT * FROM cves WHERE id_fingerprint = ?", (fingerprinter_id,))
            cve_rows = cursor.fetchall()
            #print(len(cve_rows))
            for cve_row in cve_rows:
                #print(cve_row)
                cve_finder_output += '''The following host: ''' + Add_html_color('#f1c50e',fingerprinter_row[6]) + '''\nTechnology: ''' + Add_html_color('#e500ff',fingerprinter_row[3])
                cve_finder_output += '''\nVersion: ''' + Add_html_color('#e500ff',fingerprinter_row[4]) + '''\nPort: ''' + Add_html_color('#04ff00',fingerprinter_row[5]) + '''\nVulnerable to (ID) ''' + Add_html_color('#db545a',cve_row[3])
                cve_finder_output += '''\nName: ''' + Add_html_color('#c800ff',cve_row[2]) + '''\nDescription: ''' + Add_html_color('#e68387',cve_row[7]) + '''\ncvss-score: '''
                cvss_score = float(cve_row[4])
                main_color = get_color(cvss_score)
                cve_finder_output += Add_html_color(main_color,cve_row[4]) + '''\nSeverity: ''' + Add_html_color(main_color,cve_row[8])
                payload_text = cve_row[6]
                while '\n\n' in payload_text:
                    payload_text = payload_text.replace('\n\n', '\n')
                cve_finder_output += '''\nPayload: ''' + Add_html_color('#ff0000',payload_text) + '''\nResponse:\n''' + Add_html_color('#ffffff',cve_row[5]) + '''\n\n'''


    index=0
    for fingerprinter_row in fingerprinter_rows:
        index +=1
        fingerpinter_output += Add_html_color('#69bdff',fingerprinter_row[2])
        if index != len(fingerprinter_rows):
            fingerpinter_output+=''', '''
        else:
            fingerpinter_output+='''.\n'''

    


    checkalive_output_html = textile.textile(checkalive_output)
    # print(checkalive_output_html)
    port_scanner_output_html = textile.textile(port_scanner_output)
    # print(port_scanner_output_html)    
    fingerpinter_output_html = textile.textile(fingerpinter_output)
    # print(fingerpinter_output_html)
    cve_finder_output_html = textile.textile(cve_finder_output)
    # print(cve_finder_output_html)

    fingerpinter_output_html = Add_html_color('#2cccc4',fingerpinter_output_html)

    cve_finder_output_html = Add_html_color('#2cccc4',cve_finder_output_html)
    # Close the connection
    conn.close()


    return render_template('Main-Framework-Expanded.html',checkalive_output_arg = checkalive_output_html, port_scanner_output_arg=port_scanner_output_html, fingerpinter_output_arg=fingerpinter_output_html,cve_finder_output_arg=cve_finder_output_html)



@app.route('/Finder') #For other pages
def Finder():
    logging.info('Moving to finder module')
    Finder_output_html = textile.textile("Awaiting input...")
    Finder_output_html.replace('<p>', '<p class="u-align-left u-custom-font u-font-courier-new u-text u-text-palette-4-light-2 u-text-3">')
    return render_template('Finder.html',Finder_output_arg=Finder_output_html)
@app.route('/start_finder',methods=['POST'])
def start_finder():
    logging.info('Starting finder module')
    network_hostname = request.form.get('network_hostname')
    checkbox_whois = request.form.get('checkbox_whois')
    print(network_hostname)
    print(checkbox_whois) #returns strings "On" or "None"
    if checkbox_whois == "On":
        Finder_output = Enumerator._WhoIs(network_hostname)
    else:
        Finder_output = "Please select which module to run."
    Finder_output_html = textile.textile(Finder_output)
    Finder_output_html.replace('<p>', '<p class="u-align-left u-custom-font u-font-courier-new u-text u-text-palette-4-light-2 u-text-3">')
    return render_template('Finder.html',Finder_output_arg=Finder_output_html)


def get_color_cve_classification(value, min_value, max_value):
    # Calculate the color based on the value, minimum, and maximum values
    if max_value != min_value:
        red = int(((max_value - value) / (max_value - min_value)) * 255)
        green = int(((value - min_value) / (max_value - min_value)) * 255)
        blue = 0
    else:
        red = 0
        green = 255
        blue = 0
    
    # Format the RGB values as a hexadecimal color code
    color_code = "#{:02X}{:02X}{:02X}".format(red, green, blue)
    return color_code
@app.route('/CVE-classification') 
def CVE_classification():
    logging.info('Moving to CVE-classification module')
    return render_template('CVE-classification.html',CVE_classification_output_arg='')
@app.route('/cve_api',methods=['POST'])     #pattern="CVE-\d{4}-\d+(,CVE-\d{4}-\d+)*"
def cve_api():
    logging.info('Starting to CVE-classification module')
    cve_input = request.form.get('cve_input')
    print(cve_input) #36. Use API from https://www.first.org/epss/api for CVE Classifer       | TO BE REVIEWED
    #curl https://api.first.org/data/v1/epss?cve=CVE-2022-27225,CVE-2022-27223,CVE-2022-27218
    #curl https://api.first.org/data/v1/epss?cve=CVE-2022-27225
    #curl https://api.first.org/data/v1/epss?cve=
        #Top 100

        #CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23<br> CVE-2023-33297 | epss: 0.00045 | percentile: 12.326 % | date: 2023-05-23
    command = "curl https://api.first.org/data/v1/epss?cve=" + cve_input
    #os.system(command)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    output = out.decode('ascii')
    # Find the JSON portion in the text
    start_index = output.find('{')
    end_index = output.rfind('}')
    json_text = output[start_index:end_index+1]
    parsed_output = json.loads(json_text)
    json_length = len(parsed_output['data'])
    CVE_classification_output_html = ""
    cve_epss = []
    cve_name = []
    cve_percentile = []
    cve_date = []
    for index in range(json_length):
        cve_epss.append(parsed_output['data'][index]['epss']) #ok..
        cve_name.append(parsed_output['data'][index]['cve'])
        cve_percentile.append(float(parsed_output['data'][index]['percentile']))
        cve_date.append(parsed_output['data'][index]['date'])
    percent_min_value = min(cve_percentile)
    percent_max_value = max(cve_percentile)
    for index in range(json_length):
        color = get_color_cve_classification(cve_percentile[index],percent_min_value,percent_max_value)
        CVE_classification_output_html += Add_html_color(color,cve_name[index]) + " | epss: " + cve_epss[index] + " | percentile: " + Add_html_color(color,str(cve_percentile[index])) + " % | date: " + cve_date[index]
        if index != json_length-1:
            CVE_classification_output_html += "<br>"
    return render_template('CVE-classification.html',CVE_classification_output_arg=CVE_classification_output_html)

#start_fuzzing

@app.route('/Fuzzing') 
def Fuzzing():
    logging.info('Moving to Fuzzing module')
    return render_template('Fuzzing.html',fuzzing_output_arg='')
@app.route('/start_fuzzing',methods=['POST'])
def start_fuzzing():
    logging.info('Starting to Fuzzing module')
    url_target = request.form.get('url_target')
    url_target = url_target.split(",")
    dictionary_checkbox1 = str(request.form.get('dictionary_checkbox1'))
    dictionary_checkbox2 = str(request.form.get('dictionary_checkbox2'))
    dictionary_checkbox3 = str(request.form.get('dictionary_checkbox3'))
    print(url_target)
    print(dictionary_checkbox1) # None if not selected, else "default_dictionary_10k_dictionaries.txt" or whatever is written in front of it
    print(dictionary_checkbox2)
    print(dictionary_checkbox3)
    custom_file = ""
    if 'fuzzing_custom_file' in session:
        custom_file = session['fuzzing_custom_file']
        logging.info('Using dictionary given %s' % custom_file)
        print(custom_file)
    else:
        logging.info('No custom dictionary given for fuzzing')

    #def DirBuster(urls,dictionary_path = "wordlists/default_dictionary_10k_directories.txt"):
    dirbuster_output = ""
    if dictionary_checkbox1 != "None":
        dirbuster_output += Enumerator.DirBuster(url_target,"default_wordlists/" + dictionary_checkbox1)
    if dictionary_checkbox2 != "None":
        dirbuster_output += Enumerator.DirBuster(url_target,"default_wordlists/" + dictionary_checkbox2)   
    if dictionary_checkbox3 != "None":
        dirbuster_output += Enumerator.DirBuster(url_target,"default_wordlists/" + dictionary_checkbox3)
    if custom_file != "":
        dirbuster_output += Enumerator.DirBuster(url_target,custom_file)
        os.remove(custom_file)
        session.pop('fuzzing_custom_file')
    # print(dirbuster_output)
    dirbuster_output_html = textile.textile(Add_html_color('#69bdff',dirbuster_output))
    return render_template('Fuzzing.html',fuzzing_output_arg=dirbuster_output_html)

@app.route('/start_fuzzing_custom',methods=['POST'])
def start_fuzzing_custom():
    logging.info('Starting to Custom Fuzzing module')
    file_path = ''
    file = request.files['file_upload']
    #file = request.files.get('file_upload',None)
    print(file)
    if file.filename == '':
        logging.info('No custom dictionary given')
    else:
        logging.info('Custom dictionary given %s' % file)
        upload_folder = os.path.join(app.root_path, 'tmp_uploads')
        file_path = os.path.join(upload_folder, file.filename)
        file.save(file_path)
        # g.fuzzing_custom_file = file_path
        session['fuzzing_custom_file'] = file_path
    # if not file.filename.endswith('.txt'):
    

    # os.remove(file_path)
    # if file_path != '':
    #     dirbuster_output += Enumerator.DirBuster(url_target,file_path)
    if file.filename != '':
        output = 'Custom dictionary named: "'+file.filename+'" has been uploaded successfully, you can now run the fuzzing as normal and the custom dictionary will be used as well.'
    else:
        output = 'Please select a ".txt" file if you want to use a custom dictionary.'
    return render_template('Fuzzing.html',fuzzing_output_arg=output)

@app.route('/History') #work with urls.... TO DO when processing inputs
def History():
    logging.info('Moving to History page')
    http_output = ""
    conn = sqlite3.connect('pentestframeworkdb.db')
    cursor = conn.cursor()
    # Select rows where id is the given value
    cursor.execute("SELECT * FROM reports ORDER BY timestamp DESC")
    report_rows = cursor.fetchall()
    network = ''
    timestamp = ''
    host_rows = []
    fingerprinter_rows = []
    # Print the selected rows
    for row in report_rows:
        network = ''
        timestamp = ''
        host_rows = []
        fingerprinter_rows = []
        #print(row)
        report_id = row[0]
        network = row[1]
        timestamp = row[2]
        port_count = 0
        cve_count = 0
        cursor.execute("SELECT * FROM hosts WHERE id_report = ?", (report_id,))
        host_rows = cursor.fetchall()
        for host_row in host_rows:
            #print(host_row)
            host_id = host_row[0]
            cursor.execute("SELECT COUNT(*) FROM ports WHERE id_host = ?", (host_id,))
            port_rows = cursor.fetchall()
            for port_row in port_rows:
                #print(port_row[0])
                port_count = port_row[0]
        cursor.execute("SELECT * FROM fingerprints WHERE id_report = ?", (report_id,))
        fingerprinter_rows = cursor.fetchall()
        for fingerprinter_row in fingerprinter_rows:
            #print(fingerprinter_row)
            fingerprinter_id = fingerprinter_row[0]
            cursor.execute("SELECT COUNT(*) FROM cves WHERE id_fingerprint = ?", (fingerprinter_id,))
            cve_rows = cursor.fetchall()
            for cve_row in cve_rows:
                #print(cve_row)
                cve_count = cve_row[0]
        # print(report_id)
        # print(timestamp)
        # print(port_count)
        # print(len(host_rows))
        # print(len(fingerprinter_rows))
        # print(cve_count)
        # print(network)
        # print(host_rows)
        # print(fingerprinter_rows)
        http_output += '''<tr style="height: 45px;"> <td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-first-column u-font-courier-new u-table-cell u-table-cell-6"> <a href="/history_to_main?report_id=''' +str(report_id)+'''">''' + Add_html_color('#2cccc4',str(report_id) + ''')</a> ''')  + '''</td>'''
        http_output += '''<td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-font-courier-new u-table-cell u-table-cell-7">''' + str(timestamp) + '''</td>'''
        http_output += '''<td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-font-courier-new u-table-cell u-table-cell-7">''' + str(network) + '''</td>'''
        http_output += '''<td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-font-courier-new u-table-cell u-table-cell-7">''' + str(len(host_rows)) + '''</td>'''
        http_output += '''<td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-font-courier-new u-table-cell u-table-cell-7">''' + str(port_count) + '''</td>'''
        http_output += '''<td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-font-courier-new u-table-cell u-table-cell-7">''' + str(len(fingerprinter_rows)) + '''</td>'''
        http_output += '''<td class="u-border-3 u-border-no-left u-border-no-right u-border-palette-4-base u-custom-font u-font-courier-new u-table-cell u-table-cell-7">''' + str(cve_count) + '''</td>'''
        http_output += '''</tr>'''

    conn.close()
        #GET hrefs or something in order to use start_pentest method for any history entry!!!!!!
    return render_template('History.html',history_output_arg = http_output)

@app.route('/history_to_main')
def history_to_main():
    logging.info('Redirecting from history to main framework')
    report_id = request.args.get('report_id')
    with app.app_context():
        app.pentest_report_id = report_id
        event.set()
        return Main_Framework_Expanded()

@app.route('/Help') 
def Help():
    logging.info('Moving to Help page')
    return render_template('Help.html')


@app.route('/return-to-index') #redirecting... for headers make #app.route
def return_to_index():
    logging.info('Returning to main framework')
    return main()

if __name__ == '__main__':
    app.run()
