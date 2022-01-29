'''
William Orozco
worozco at ucdavis dot edu
January 2022
References:
https://github.com/vnetman/pcap2csv/blob/master/pcap2csv.py
https://github.com/KimiNewt/pyshark

'''

import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP


import json

parameters = json.load(open('parameters.json'))
path = parameters["datapath"]
filename = 'test-2g-01_10_2022-00_10_42.pcap'
pcap_pyshark = pyshark.FileCapture(path+filename)

desired_df_columns=['Time since first frame in this TCP stream',
                    'Source',
                    'Destination',
                    'Stream index',
                    'Time',
                    'TCP Segment Len',
                    'Retransmission']

print(pcap_pyshark[3000].tcp.time_relative)
print(pcap_pyshark[3000].tcp.time_delta)
print(pcap_pyshark[3000].ip.src_host)
print(pcap_pyshark[3000].ip.dst_host)
print(pcap_pyshark[3000].tcp.stream)
print(pcap_pyshark[3002].tcp.len)
