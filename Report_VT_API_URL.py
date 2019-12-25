#    VT_API_URL_Results.py  CAO: 20190508
#    Written by Evan Daman
#
#    Replace "<APIKEY>" with apikey...
#
#    This script will take an input lookup table with one column containing
#    domain names you wish to check virus total scores on.
#
#    Please delete the column label in cell 1. 
#    Please deduplicate the list to be nice to VT.
#
#    Lookup tables must be saved to the script's directory
#
#    Will pull results and save them to central a directory by domain name.
#    
#    Will output domain name and score if > 1 to stdout.


import requests
import json
import datetime
import os
import time
import re

REGEX = re.compile(r':443[0-9][0-9]')

#Create folder at run time with current date and time
timeKeeper = datetime.datetime.now()
FOLDER = timeKeeper.strftime("%Y%m%d-%H%M_VT_Domain_Results")
print "Files will be saved to directory: ", FOLDER
path = FOLDER
os.mkdir(path)
time.sleep(5)


####Open these files for the duration of the program
INFILE = open('url-list.csv', 'r')
RESULTS = open('ReportResults.log', 'a+')
RESULTS.write('\n\n')
RESULTS.write("===============Results for ")
RESULTS.write(timeKeeper.strftime("%Y%m%d-%H%M"))
RESULTS.write("===============")
RESULTS.write('\n\n')


####Change Directories for ease of file creation
os.chdir(path)
#PWD = os.getcwd()
#print("PWD=",PWD)


#For each line in the input file.
for line in INFILE:


####strip newlines and quotes from the lookup table. 
####Also converts Break and Inspect's port specification back to :443
    URL = line.replace('\n','').replace('"','').strip('/')
    URLBI = REGEX.sub(':443',URL)
    #print URLBI

####Set the options for requests.get request.
    HEADERS = {'content-type': 'application/json', 'Accept-Encoding': 'gzip, deflate'}
    PARAMS = {'apikey':'<APIKEY>','resource':URLBI}
    r = requests.get(url = 'https://www.virustotal.com/vtapi/v2/url/report', params = PARAMS, headers=HEADERS)


####Parse the json from get request, assign json value of positives to variable to convert to an integer later
    json_response = r.json()
    positives = json_response['positives']
    

####open, write and close file that has the name of domain from input
    FILENAME = URL.replace('/', '~')
    if len(FILENAME) > 75:
        FILENAME = (FILENAME[:75] + '..')
    else:
        FILENAME
    OUTFILE = open(FILENAME, 'w+') 
    with OUTFILE as fd:
        for chunk in r.iter_content(chunk_size=128):
            fd.write(chunk)
    OUTFILE.close()
    

####Does not print to stdout if score is less than 1. Writes positive hits to log.
    if int(positives)< 1:
        #print positives
        continue
    else:
        #print positives
        print positives,'\t',URL
        RESULTS.write(str(positives))
        RESULTS.write('\t')
        RESULTS.write(URL)
        RESULTS.write('\n')

INFILE.close()
RESULTS.close()
