'''
Script to return RTT, throughput and packet loss based on a pcap file previously exported as csv with wireshark.

SCRIPT TO PLOT MULTIPLE SERIES IN SAME PLOT.

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
files=[] # leave empty, for automatic file name appending
no_files = 4
filename = 'csv2gpython_'
extension='.csv'
BANDWIDTH = 2
TOP_BW_AXIS = BANDWIDTH+1
BOTTOM_BW_AXIS = BANDWIDTH-1
desired_df_columns=['Time since first frame in this TCP stream',
                    'Source',
                    'Destination',
                    'Stream index',
                    'Time',
                    'TCP Segment Len',
                    'Retransmission']

TCP_WINDOW_SIZE = 65535 # in Bytes
#Gbs_scale_factor = 1000000000 * math.sqrt(2) # for some reason, the calculated value is scaled by sqrt(2), so should divide by this.
Gbs_scale_factor = 1000000000
ms_scale_factor = 1000
stream_index = 1

remove_from_plot = [5, 6, 7, 9]

'''
define functions
'''
# generate filenames by appending a number to a base filename
def get_filenames(no_files=no_files,filename=filename,extension=extension,files_array=files):
    for i in range(1, no_files+1):
        files_array.append(filename+str(i)+extension)
    return files_array

#read files and return the dataframe with the required columns
def read_files(files_array, path=path):
    df_array=[]
    for i,filename in enumerate(files_array):
        #read csv file and convert to pandas dataframe
        df_temp=pd.read_csv(path+filename)
        print('reading: '+path+filename)
        #print(df_temp.keys())

        #drop not desired columns to avoid extra memory
        for i, key in enumerate(df_temp.keys()):
            if key not in desired_df_columns:
                df_temp=df_temp.drop(columns=key)
        #df_temp.dropna()
        df_array.append(df_temp)
    return df_array


#df = pd.read_csv(path+filename)

# filter traffic sent from vm1 to vm4, drop the rest
def filter_packets_vm1_vm4(df_array):
    df_out=[]
    for df in df_array:
        df=df[(df['Source'] == '10.0.0.1')
         & (df['Destination'] == '10.0.0.4')
         & (df['Stream index'] == stream_index)]
        #df.dropna()
        df_out.append(df)
    return df_out


'''
Processing section
'''
files_array = get_filenames()
df_array = read_files(files_array)
t_axis = df_array[0]['Time since first frame in this TCP stream']


'''
*********************************************************************
plotting
*********************************************************************
'''

print('-------plotting-------')
# -----------------------------------
# plot RTT, vertical axis in ms.
# -----------------------------------
plt.figure()
#plt.scatter(df2['Time since first frame in this TCP stream'], 1000*(df2['Time'].rolling(1000).mean()))
for i,df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.plot(df['Time since first frame in this TCP stream'], df['Time'] * ms_scale_factor, label='test ' + str(i))
plt.title(filename + " - RTT")
plt.xlabel("t (s)")
plt.ylabel("RTT (ms)")
plt.grid('on')
plt.legend()

# -----------------------------------
# plot TCP segment length
# -----------------------------------
plt.figure()
#plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len'].rolling(1000).mean()))
for i,df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.scatter(df['Time since first frame in this TCP stream'], (df['TCP Segment Len']), label='test ' + str(i))
plt.title(filename + " - TCP segment length (bits)")
plt.xlabel("t (s)")
plt.grid('on')
#plt.ylim(66000)
plt.ylabel("TCP Segment len (Bytes)")
plt.grid('on')
plt.legend()

# -----------------------------------
# plot Throughput as the ratio of the moving average of TCP segment length / RTT
# -----------------------------------
plt.figure()
#create a new entry in the dataframe for the throughput with Moving Average
#https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i,df in enumerate(df_array):
    if i not in remove_from_plot:
        df['Throughput'] = (8*df['TCP Segment Len']/df['Time']).rolling(1000).mean()
        #plt.scatter(df2['Time since first frame in this TCP stream'], df2['Throughput'])
        plt.plot(df['Time since first frame in this TCP stream'], 8 * ((df['TCP Segment Len'].rolling(10000).mean()) / (df['Time'].rolling(10000).mean())) / Gbs_scale_factor, label='test ' + str(i))
        #plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len']/(df2['Time']).rolling(1000).mean() / 1024000))

plt.title(filename + " - Throughput (Gbps) WND/RTT")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=TOP_BW_AXIS, bottom=BOTTOM_BW_AXIS)
plt.grid('on')
plt.legend()

# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Length'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['Length'].rolling(1000).mean())/(df2['Time'].rolling(1000).mean())/1000000)
# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Length'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Time'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['Length'].rolling(1000).mean())/(df2['Time'].rolling(1000).mean())/1000000)


# =============================================================================================================================
# Calculate packets sent, retransmissions and packet loss ratio

pkt_sent_array_series=[]
pkt_retransmit_array_series=[]
pkt_loss_ratio_array_series=[]
for i, df in enumerate(df_array):
    # now group retransmissions each second.
    # convert time index to integer
    # https://www.geeksforgeeks.org/convert-floats-to-integers-in-a-pandas-dataframe/
    print('working on df: '+str(i))
    #df = df.dropna()

    # drop na values on the column that we are going to convert to integer
    # https: // stackoverflow.com / questions / 13413590 / how - to - drop - rows - of - pandas - dataframe - whose - value - in -a - certain - column - is -nan
    df = df[df['Time since first frame in this TCP stream'].notna()]
    df['Time since first frame in this TCP stream'] = df['Time since first frame in this TCP stream'].astype(int)
    #print(df.keys())
    #print(df['Retransmission'].unique())

    # convert retransmissions column to int
    df['Retransmission'] = df['Retransmission'].replace(df['Retransmission'].unique()[0], 0) #first element should be NaN for not retransmission
    df['Retransmission'] = df['Retransmission'].replace(df['Retransmission'].unique()[1], 1) # second element should be a weird string of len 9, for retransmission

    # count all the packets, no matter if lost or sent successfully.
    pkt_sent=df.groupby('Time since first frame in this TCP stream')['Retransmission'].count()
    print('pkt sent mean: '+str(pkt_sent.mean()))
    pkt_sent_array_series.append(pkt_sent)
    # add all the retransmissions per second, as a metric for packet loss
    pkt_retransmit=df.groupby('Time since first frame in this TCP stream')['Retransmission'].sum()
    pkt_retransmit_array_series.append(pkt_retransmit)
    # calculate the packet loss metric
    pkt_loss_ratio_array_series.append(100*pkt_retransmit/pkt_sent)

# Now plot the results.
# -----------------------------------
# Plot sent packets per second
# -----------------------------------
plt.figure()
for i, pkt_sent in enumerate(pkt_sent_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_sent, label='test ' + str(i))
plt.title(filename + " - Packets sent")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")
plt.grid('on')
plt.legend()

# -----------------------------------
# Plot retransmitted packets per second
# -----------------------------------
plt.figure()
for i,pkt_retransmit in enumerate(pkt_retransmit_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_retransmit, label='test ' + str(i))
plt.title(filename + " - Packets retransmitted")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")
plt.grid('on')
plt.legend()

# -----------------------------------
# Plot packet loss metric
# -----------------------------------
plt.figure()
for i,pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_loss_ratio, label='test ' + str(i))
plt.title(filename + " - packet loss ratio")
plt.xlabel("t (s)")
plt.ylabel("%")
plt.grid('on')
plt.legend()

# -----------------------------------
# Plot calculated throughput as packets sent * TCP Window size
# -----------------------------------
plt.figure()
for i, pkt_sent in enumerate(pkt_sent_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_sent * TCP_WINDOW_SIZE * 8 / Gbs_scale_factor/2,label='test ' + str(i))
plt.title(filename + " - TCP Throughput as packets sent * TCP Window Size ")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=TOP_BW_AXIS, bottom=BOTTOM_BW_AXIS)
plt.grid('on')
plt.legend()

plt.show()
