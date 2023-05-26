import subprocess

import aiofiles
import asyncio

async def Async_Write_To_File(String,Filepath):
    async with aiofiles.open(Filepath, mode='w') as f:
        await f.write(String)

#asyncio.run(Async_Write_To_File(string,filepath))


class Enumerator:

    def __init__(self,IP): #ip or IP list?
        self.IP_address = str(IP)
        print("Starting Enumerator module on IP:" + self.IP_address)


    def _WhoIs(self):
        #log ...
        command = "whois " + self.IP_address
        #os.system(command)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        print("_______START OF WHOIS METHOD OUTPUT_______")
        print(out.decode('ascii'))
        print("_______END OF WHOIS METHOD OUTPUT_______")

        """
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '213.177.4.160 - 213.177.4.175'

% Abuse contact for '213.177.4.160 - 213.177.4.175' is 'abuse@stsisp.ro'

inetnum:        213.177.4.160 - 213.177.4.175
netname:        MTA-NET
descr:          Academia Tehnica Militara
source:         RIPE

person:         Minta Adrian
address:        Special Telecommunications Service
address:        323A Splaiul Independentei, Bucharest 6
phone:          +40212022660
nic-hdl:        MA3173-RIPE
mnt-by:         ROSTS-MNT
created:        2004-04-05T11:49:55Z
last-modified:  2018-02-01T08:42:56Z
source:         RIPE # Filtered

% Information related to '213.177.0.0/21AS31313'

route:          213.177.0.0/21
descr:          STS infrastructure and customers
origin:         AS31313
mnt-by:         ROSTS-MNT
created:        2016-02-01T09:01:07Z
last-modified:  2016-02-01T09:01:07Z
source:         RIPE

% This query was served by the RIPE Database Query Service version 1.106.1 (DEXTER)
"""
    ##Bruteforce directories, dirbuster style, use default 2 custom made dictionaries | if users wants to input themselves, let them through GUI later
        #we use command "dirb" for dirbuster in command line!

    def DirBuster(urls,dictionary_path = "wordlists/default_dictionary_10k_directories.txt"):
        print(urls)
        for url_index in range(len(urls)):
            #log ...    
            command = "dirb " + urls[url_index] + " " +  dictionary_path +" -S"
            #os.system(command)
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
            (out, err) = proc.communicate()
            print("_______START OF DIRBUSTER METHOD OUTPUT_______")
            print(out.decode('ascii'))
            print("_______END OF DIRBUSTER METHOD OUTPUT_______")

            asyncio.run(Async_Write_To_File(out.decode('ascii'),"temp_dirb"+ str(url_index) +".txt")) #>> temp_dirb" + ".txt" #DO BETTER (TMP DIRECTORY)


