#    VT_API_URL_Results.py  CAO: 20190509
#    Written by Evan Daman, evan.s.daman.ctr@mail.mil
#    This script will take an input lookup table with one column containing
#    domain names you wish to check virus total scores on.
#
#    Replace "<APIKEY>" with apikey...
#
#    Please remove the column label in cell one.
#    Please deduplicate the table to be nice to VT
#
#    Lookuptable must be saved to script's working directory.
#
#    You must run this script and then the script to pull reports.


import requests
import json
import datetime
import os
import time
import re

REGEX = re.compile(r':443[0-9][0-9]')

print "Output will be appended to ScanResults.log"
time.sleep(5)
####Open this file for the duration of the program
INFILE = open('url-list.csv', 'r')


#For each line in the input file.
for line in INFILE:


####strip newlines and quotes from the lookup table
####Also converts break and inspect's port specifications back to :443
    URL = line.replace('\n','').replace('"','').strip('/')
    URLBI = REGEX.sub(':443',URL)
    #print URLBI


####Set the options for requests.get request.
    headers = {'content-type': 'application/json', 'Accept-Encoding': 'gzip, deflate'}
    PARAMS = {'apikey':'<APIKEY>','url':URLBI}
    r = requests.post(url = 'https://www.virustotal.com/vtapi/v2/url/scan', params = PARAMS, headers=headers)
    print r.json()['verbose_msg']
    print URL,'\n'

####open, write and close file that has the name of domain from input
    LOGFILE = open('ScanRequest.log', 'a+') 
    LOGFILE.write(r.json()['verbose_msg'])
    LOGFILE.write('\n')
    LOGFILE.write(URL)
    LOGFILE.write('\n\n')

INFILE.close()

