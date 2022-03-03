'''
William Orozco
worozco at ucdavis dot edu
February 2022

Convert
References:
https://stackoverflow.com/questions/60228142/how-to-execute-tshark-in-python-for-every-file-in-a-folder
https://shantoroy.com/networking/convert-pcap-to-csv-using-tshark/
https://stackoverflow.com/questions/47319313/get-filenames-in-a-directory-without-extension-python
https://www.geeksforgeeks.org/python-os-path-splitext-method/
'''

import os
import subprocess
import json

parameters = json.load(open('parameters.json'))
path = parameters["datapath"]

df_headers = ['tcp.time_relative',
              'ip.src',
              'ip.dst',
              'tcp.stream',
              'tcp.time_delta',
              'tcp.len',
              'tcp.window_size',
              'tcp.analysis.retransmission']

# get the file list in the directory
path_files = os.listdir(path)


print ("reading pcap /writing csv in: "+path)
for pcap_file in os.listdir(path):
     # analyze only pcap files
     if pcap_file.endswith(".pcap"):
         #os.path.splitext returns in  position 0 the fileneme, in position 1 the extension
         #TODO check if the csv file already exists.
         #if (os.path.splitext(pcap_file)[0] + '.csv') in os.listdir(path):
         #   filename = os.path.splitext(pcap_file)[0] + '.csv'
         filename = os.path.splitext(pcap_file)[0] + '.csv'
         # write the csv file if not already in the folder.
         if filename not in os.listdir(path):
             args = ['tshark', '-r', os.path.join(path, pcap_file),
                     '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d', '-E', 'occurrence=a',
                     '-e', 'ip.ttl', '-e', 'ip.src', '-e', 'ip.dst',
                     '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'tcp.seq', '-e', 'tcp.ack',
                     '-e', 'tcp.len', '-e', 'tcp.seq', '-e', 'tcp.nxtseq',
                     '-e', 'tcp.time_delta', '-e', 'tcp.time_relative', '-e', 'tcp.stream',
                     '-e', 'tcp.analysis.retransmission', '-e', 'tcp.analysis.lost_segment',
                     '-e', 'tcp.window_size', '-q']
             with open(path+filename,"w") as outfile:
                 print("writing: " + filename)
                 subprocess.run(args, stdout=outfile, check=True)
         else:
             print(filename + " already exists on " + path)

print("------Finished-------")