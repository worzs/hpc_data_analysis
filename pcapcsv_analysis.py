'''
Script to return RTT, throughput and packet loss based on a pcap file previously exported as csv with wireshark.

William Orozco
worozco at ucdavis.edu
December 2021

TO BE EXECUTED in any computer/server where the csv file is stored. The pcap file currently is captured in server vm1, then pulled with filezilla to my laptop.

Required columns: Source, Destination, Stream index, Time since first frame in this TCP stream, Time, TCP Segment Len, Retransmission
'''
import math
import pandas as pd
import matplotlib.pyplot as plt

import json

parameters = json.load(open('parameters.json'))
path = parameters["datapath"]

TCP_WINDOW_SIZE = 65535 # in Bytes
Gbs_scale_factor = 1000000000 * math.sqrt(2) # for some reason, the calculated value is scaled by sqrt(2), so should divide by this.
ms_scale_factor = 1000
stream_index = 1



filename = 'csv2gpython.csv'

df = pd.read_csv(path+filename)

# filter traffic sent from vm1 to vm4
df2 = df[(df['Source'] == '10.0.0.1')
         & (df['Destination'] == '10.0.0.4')
         & (df['Stream index'] == stream_index)]
# remove NA rows
df2.dropna()

# -----------------------------------
# plot RTT, vertical axis in ms.
# -----------------------------------
plt.figure()
#plt.scatter(df2['Time since first frame in this TCP stream'], 1000*(df2['Time'].rolling(1000).mean()))
plt.plot(df2['Time since first frame in this TCP stream'], df2['Time'] * ms_scale_factor)
plt.title(filename + " - RTT")
plt.xlabel("t (s)")
plt.ylabel("RTT (ms)")
plt.grid('on')

# -----------------------------------
# plot TCP segment length
# -----------------------------------
plt.figure()
#plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len'].rolling(1000).mean()))
plt.scatter(df2['Time since first frame in this TCP stream'], (df2['TCP Segment Len']))
plt.title(filename + " - TCP segment length (bits)")
plt.xlabel("t (s)")
plt.grid('on')
#plt.ylim(66000)
plt.ylabel("TCP Segment len (Bytes)")
plt.grid('on')


# -----------------------------------
# plot Throughput
# -----------------------------------
plt.figure()
#create a new entry in the dataframe for the throughput with Moving Average
#https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
df2['Throughput'] = (8*df2['TCP Segment Len']/df2['Time']).rolling(1000).mean()
#plt.scatter(df2['Time since first frame in this TCP stream'], df2['Throughput'])
plt.plot(df2['Time since first frame in this TCP stream'], 8 * ((df2['TCP Segment Len'].rolling(10000).mean()) / (df2['Time'].rolling(10000).mean())) / Gbs_scale_factor )
#plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len']/(df2['Time']).rolling(1000).mean() / 1024000))
plt.title(filename + " - Throughput (Gbps) WND/RTT")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=10,bottom=0)
plt.grid('on')

# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Length'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['Length'].rolling(1000).mean())/(df2['Time'].rolling(1000).mean())/1000000)
# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Length'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Time'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['Length'].rolling(1000).mean())/(df2['Time'].rolling(1000).mean())/1000000)


# =============================================================================================================================
# now group retransmissions each second.


# convert time index to integer
# https://www.geeksforgeeks.org/convert-floats-to-integers-in-a-pandas-dataframe/
df2['Time since first frame in this TCP stream'] = df2['Time since first frame in this TCP stream'].astype(int)

# convert retransmissions column to int
df2['Retransmission'] = df2['Retransmission'].replace(df2['Retransmission'].unique()[0], 0) #first element should be NaN for not retransmission
df2['Retransmission'] = df2['Retransmission'].replace(df2['Retransmission'].unique()[1], 1) # second element should be a weird string of len 9, for retransmission

# count all the packets, no matter if lost or sent successfully. 
pkt_sent = df2.groupby('Time since first frame in this TCP stream')['Retransmission'].count()
# add all the retransmissions per second, as a metric for packet loss
pkt_retransmit = df2.groupby('Time since first frame in this TCP stream')['Retransmission'].sum()

# calculate the packet loss metric
pkt_loss_ratio = 100*pkt_retransmit/pkt_sent

# Now plot the results.
# Plot sent packets per second
plt.figure()
plt.plot(pkt_sent)
plt.title(filename + " - Packets sent")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")
plt.grid('on')

# Plot retransmitted packets per second
plt.figure()
plt.plot(pkt_retransmit)
plt.title(filename + " - Packets retransmitted")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")
plt.grid('on')

# Plot packet loss metric
plt.figure()
plt.plot(pkt_loss_ratio)
plt.title(filename + " - packet loss ratio")
plt.xlabel("t (s)")
plt.ylabel("%")
plt.grid('on')

# Plot throughput
plt.figure()
plt.plot(pkt_sent * TCP_WINDOW_SIZE * 8/ Gbs_scale_factor)
plt.title(filename + " - TCP Throughput as packets sent * TCP Window Size ")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.grid('on')

plt.show()
