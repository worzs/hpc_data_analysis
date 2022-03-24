'''
William Orozco
worozco at ucdavis dot edu
January 2021

Script to return RTT, throughput and packet loss based on a pcap file previously exported as csv with wireshark.

Plot multiple series in one plot, stateless approach with matplotlib
https://realpython.com/python-matplotlib-guide/

TO BE EXECUTED in any computer/server where the csv file is stored.
Required columns: ip.src, ip.dst, tcp.stream, tcp.time_relative, tcp.time_delta, tcp.len, tcp.analysis.retransmission

'''

import math
import pandas as pd
import matplotlib
matplotlib.use('Qt5Agg', force=True) #fix for use qt5agg backend for matplotlib. Use $pip install pyqt5
# https://python-graph-gallery.com/custom-fonts-in-matplotlib
matplotlib.rcParams['font.family'] = 'cmr10' #for labels, titles, and other text
matplotlib.rcParams['mathtext.fontset'] = 'cm'
matplotlib.rcParams['font.size'] = 13
import matplotlib.pyplot as plt
from matplotlib.ticker import (AutoMinorLocator, MultipleLocator)
import json
import os

#use this commands to find the available fonts, or at least, to find the folder where ttfs are stored.
#from matplotlib import font_manager
#font_manager.findfont("cmr10")

# the following 2 lines can be replaced by only path=<INSERT_PATH_HERE>". I chose this way to avoid submitting my laptop directories to github.
parameters = json.load(open('parameters.json'))
path = parameters["datapath"]

files_array=[] # leave empty, for automatic file name appending

#for analyzing csv files in path
for file in os.listdir(path):
    # analyze only pcap files
    if (file.endswith(".csv")):# and ('v1' in file):
        files_array.append(file)
files_array.sort()

TEST_ID=1
#files_array=[files_array[TEST_ID],files_array[TEST_ID+50]]
files_array=files_array[2:3]


remove_from_plot=[]
#remove_from_plot.extend(list(range(0,10)))
#remove_from_plot.extend(list(range(20,50)))

#parameters for automatic filename generation
no_files = 1
#the following two parameters help when more than 1 experiment is going to be analyzed at the same bandwidth.
filename = ''
if 'MBB' in path:
    filename+= 'Make before break v3'
elif 'OST' in path:
    filename += 'Optical switching v1'

if 'Dual' in path:
    filename+=' - Bandwidth steering '

#filename = 'Make before break - Bandwidth steering v1'
extension = '.csv'

BOXPLOT_MBB_SPACED = False
STEADY_INDEX = 2
LABEL_RIGHT_LIMIT = 3 # last element of filename standard to include in plot label
TEST_DURATION = 20
RECONFIGURATION = 10
XAXIS_LOCATOR = 2 # for xticklabels. 2 for test duration 20, and 10 for test duration 60

markers = ['>', '+', '.', ',', 'o', 'v', 'x', 'X', 'D', '|']
MARKER_SIZE = 10
MARKER_EVERY_S = 4 #add a marker to the time series every N seconds.
PIXEL_W=640 #for plot size
PIXEL_H=480
px = 1/plt.rcParams['figure.dpi'] #get dpi for pixel size setting

BANDWIDTH = 10
TOP_BW_AXIS = 10
BOTTOM_BW_AXIS = 0
desired_df_columns = ['tcp.time_relative',
                      'ip.src',
                      'ip.dst',
                      'tcp.srcport',
                      'tcp.dstport',
                      'tcp.stream',
                      'tcp.time_delta',
                      'tcp.len',
                      'tcp.window_size',
                      'tcp.analysis.retransmission',
                      #'tcp.analysis.bytes_in_flight',
                      'tcp.analysis.ack_rtt']

#factors for modifying the rolling window size of moving average
ROLLING_FACTOR=1 # used for calculating average throughput. rolling 1 second means SMA 1, rolling N means SMA 1/N seconds
ALPHA=0.5
ROLLING_FACTOR_TIME_DELTA=2 # used for calculating average RTT. rolling 1 second means SMA 1s, rolling N means SMA 1/N seconds
ROLLING_FACTOR_RTT_ACK=2 # used for calculating average RTT. rolling 1 second means SMA 1s, rolling N means SMA 1/N seconds

ROLLING_FACTOR_LOSS = 1 #used for calculating average loss. rolling 1 second means SMA 1s, rolling N means SMA 1/N seconds

TCP_WINDOW_SIZE = 65535  # in Bytes
Gbs_scale_factor = 1000000000
ms_scale_factor = 1000
kbps_scale_factor = 1000
SPLIT_FILENAME_CHAR=')'
#stream_index = 1





'''
define functions
'''


# generate filenames by appending a number to a base filename
def get_filenames(no_files=no_files, filename=filename, extension=extension):
    for i in range(1, no_files + 1):
        files_array.append(filename + str(i) + extension)
    return files_array


# read files and return the dataframe with the required columns
def read_files(files_array, path=path):
    df_array = []
    for i, filename in enumerate(files_array):
        # Read csv file and convert to pandas dataframe. Pull only relevant columns
        df_temp = pd.read_csv(path + filename, usecols=desired_df_columns, encoding="ISO-8859-1") #fix for pandas 1.4
        print('reading: ' + path + filename)
        df_array.append(df_temp)
    return df_array

def set_time_float_to_int(df_array, column='tcp.time_relative'):
    df_out = []
    for df in df_array:
        df[column] = df[df[column].notna()][column].astype(int)
        df_out.append(df)
    print('converting time axis to int')
    return df_out

def find_pkt_sent(df_array,stream_index):
    pkt_sent_array = []
    for i, df in enumerate(df_array):
        series=df[df['tcp.stream'] == stream_index[i]].groupby('tcp.time_relative')['ip.src'].count()
        pkt_sent_array.append(series)
    print('finding pkt sent series')
    return pkt_sent_array

def find_rolling_sma_window(pkt_sent_array):
    rolling_window_array = []
    for pkt_sent in pkt_sent_array:
        rolling_window = int(pkt_sent.mean())
        rolling_window_array.append(rolling_window)
    print('finding rolling sma window')
    return rolling_window_array


# filter traffic of the actual tcp stream, drop the rest.
# the pcap file show the data stream on ID 0 or 1. Must identify and filter the right tcp stream ID.
# https://datagy.io/python-get-dictionary-key-with-max-value/
def find_stream_index(df_array):
    stream_index=[]
    for df in df_array:
        # get unique Stream IDs
        packets_per_stream = {}  # key: unique stream_id, value: packets per stream
        for index in df['tcp.stream'].unique():
            packets_per_stream[index] = df[df['tcp.stream'] == index]['tcp.stream'].count()
        #max_stream_index_value = max(packets_per_stream.values()) #to obtain the maximum value in dict.values()
        stream_index.append(max(packets_per_stream, key=packets_per_stream.get)) #obtain the key of the max value in dict.values()
    return stream_index

def filter_packets(df_array, stream_index):
    df_out = []
    for i, df in enumerate(df_array):
        df = df[ #((df['ip.src'] == '10.0.0.1') | (df['ip.src'] == '10.0.0.2'))
                #&((df['ip.dst'] == '10.0.0.4') | (df['ip.dst'] == '10.0.0.3'))
                (df['tcp.stream'] == stream_index[i])]
        df_out.append(df)
    return df_out


def find_packet_loss(df_array):
    df_out=[]
    for i, df in enumerate(df_array):
        #df['tcp.analysis.retransmission'] = df['tcp.analysis.retransmission'].replace(df['tcp.analysis.retransmission'].unique()[0], 0)
        #try:
        #    df['tcp.analysis.retransmission'] = df['tcp.analysis.retransmission'].replace(df['tcp.analysis.retransmission'].unique()[1], 1)
        #except:
        #    print('No tcp.analysis.retransmissions found')
        df['loss'] = \
        df[df['tcp.time_relative'].notna()]['tcp.analysis.retransmission'].rolling(int(rolling_sma_window_array[i] / ROLLING_FACTOR_LOSS)).sum() / \
        df[df['tcp.time_relative'].notna()]['tcp.analysis.retransmission'].rolling(int(rolling_sma_window_array[i] / ROLLING_FACTOR_LOSS)).count() * 100
        df_out.append(df)
    return df_out

def set_retransmission_values(df_array):
    df_out=[]
    for i, df in enumerate(df_array):
        df['tcp.analysis.retransmission'] = df['tcp.analysis.retransmission'].replace(df['tcp.analysis.retransmission'].unique()[0], 0)
        try:
            # second element should be a weird string of len 9, for tcp.analysis.retransmission
            df['tcp.analysis.retransmission'] = df['tcp.analysis.retransmission'].replace(df['tcp.analysis.retransmission'].unique()[1], 1)
        except:
            print('No tcp.analysis.retransmissions found')
        df_out.append(df)
    return df_out

'''
Processing section
'''
if len(files_array)==0:
    files_array = get_filenames()
df_array = read_files(files_array)
stream_index=find_stream_index(df_array)
#df_array=filter_packets(df_array, stream_index)
df_array_time_int = set_time_float_to_int(df_array)
pkt_sent_array = find_pkt_sent(df_array_time_int, stream_index)
rolling_sma_window_array = find_rolling_sma_window(pkt_sent_array)
df_array = read_files(files_array)
df_array=filter_packets(df_array,stream_index)
df_array=set_retransmission_values(df_array)
df_array=find_packet_loss(df_array)

#df_array[0]['tcp.time_relative']=df_array[0]['tcp.time_relative']-1
'''
*********************************************************************
plotting
*********************************************************************
'''

print('-------plotting-------')
# -----------------------------------
# plot ACK RTT, vertical axis in ms.
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            df[(df['tcp.time_relative'].notna()) & (df['tcp.analysis.ack_rtt'].notna()) & (df['tcp.srcport']==5201)]['tcp.time_relative'],
            df[(df['tcp.time_relative'].notna())
               & (df['tcp.analysis.ack_rtt'].notna())
               & (df['tcp.srcport']==5201)]
            ['tcp.analysis.ack_rtt'].ewm
                            (
                                span=int(len(df[(df['tcp.time_relative'].notna())
                                   & (df['tcp.analysis.ack_rtt'].notna())
                                   & (df['tcp.srcport']==5201)])/TEST_DURATION/ROLLING_FACTOR_RTT_ACK)
                            ).mean() * ms_scale_factor,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$'+ str(i+1)),
            # https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
        #print("rolling sma: " + str(rolling_sma_window_array[i]))
        #print("len rtt_ack array: " + str(len(df[(df['tcp.time_relative'].notna())
        #               & (df['tcp.analysis.ack_rtt'].notna())
        #               & (df['tcp.srcport']==5201)])))
ax1.set(title=(filename + " - ACK RTT"),
        xlabel="t (s)",
        ylabel="RTT (ms)",
        ylim=[-0.1,5],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(1))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
# adjust figure width and legend position
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))

else:
    ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')


'''
#except during congestion, this plot remains almost constant
# -----------------------------------
# plot TCP window size, vertical axis in KB.
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            df[(df['tcp.time_relative'].notna()) & (df['tcp.analysis.ack_rtt'].notna()) & (df['tcp.srcport']==5201)]['tcp.time_relative'],
             df[(df['tcp.time_relative'].notna())
                       & (df['tcp.analysis.ack_rtt'].notna())
                       & (df['tcp.srcport']==5201)]['tcp.window_size'].rolling
                 (
                    int(len(df[(df['tcp.time_relative'].notna())
                    & (df['tcp.analysis.ack_rtt'].notna())
                    & (df['tcp.srcport'] == 5201)]) / TEST_DURATION / ROLLING_FACTOR_RTT_ACK)
                 ).mean() / kbps_scale_factor ,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$'+ str(i+1)),
            # https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
ax1.set(title=(filename + " - Rcv Window size"),
        xlabel="t (s)",
        ylabel="Rcv Win (KB)",
        ylim=[2500,3200],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(200))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))

else:
    ax1.legend(loc='lower right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')
'''



'''
# -----------------------------------
# plot TCP bytes in flight, vertical axis in KB.
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            df[(df['tcp.time_relative'].notna()) & (df['tcp.analysis.bytes_in_flight'].notna()) & (df['tcp.dstport']==5201)]['tcp.time_relative'],
             df[(df['tcp.time_relative'].notna())
                       & (df['tcp.analysis.bytes_in_flight'].notna())
                       & (df['tcp.dstport']==5201)]['tcp.analysis.bytes_in_flight'].rolling
                 (
                    int(len(df[(df['tcp.time_relative'].notna())
                    & (df['tcp.analysis.bytes_in_flight'].notna())
                    & (df['tcp.dstport'] == 5201)]) / TEST_DURATION / ROLLING_FACTOR_RTT_ACK)
                 ).mean() / kbps_scale_factor ,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$'+ str(i+1)),
            # https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
print("len bytes in flight: "
      + str(len(df[(df['tcp.time_relative'].notna()) & (df['tcp.analysis.bytes_in_flight'].notna()) & (df['tcp.dstport']==5201)]['tcp.time_relative'])))
ax1.set(title=(filename + " - Bytes sent"),
        xlabel="t (s)",
        ylabel="Bytes sent (KB)",
        ylim=[10,3200],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(200))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='lower right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')
'''



'''
#tricky, ack_rtt and bytes_in_flight are not in the same index of time_relative. Need to interpolate. 
#Calculated throughput is not the same as the one calculated with other throughput plot. 
# -----------------------------------
# plot throughput v1 bytes in flight / rtt
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            #df[(df['tcp.time_relative'].notna()) & (df['tcp.analysis.ack_rtt'].notna()) & (df['tcp.srcport']==5201)]['tcp.time_relative'],
            #8* df[(df['tcp.time_relative'].notna())
            #           & (df['tcp.analysis.ack_rtt'].notna())
            #           & (df['tcp.srcport']==5201)]['tcp.window_size'].rolling(int(rolling_sma_window_array[i] / ROLLING_FACTOR_TIME_DELTA)).mean() / kbps_scale_factor ,
            df['tcp.time_relative'],
            8 * ((df['tcp.analysis.bytes_in_flight'].interpolate(method='linear',maxgap=2).ewm(span=int(rolling_sma_window_array[i] / ROLLING_FACTOR_TIME_DELTA)).mean())/
                 (df['tcp.analysis.ack_rtt'].interpolate(method='linear',maxgap=2).ewm(span=int(rolling_sma_window_array[i] / ROLLING_FACTOR_TIME_DELTA)).mean())) /
                 Gbs_scale_factor,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$'+ str(i+1)),
            # https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )

ax1.set(title=(filename + " - Throughput (Bytes out / RTT)"),
        xlabel="t (s)",
        ylabel="Throughput (Gbps)",
        ylim=[0,11],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(2))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='lower right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')
'''


# -----------------------------------
# plot tcp.time_delta, iperf data rate, vertical axis in ms.
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            df[df['tcp.time_relative'].notna()]['tcp.time_delta'].rolling(int(rolling_sma_window_array[i]/ROLLING_FACTOR_TIME_DELTA)).mean() * ms_scale_factor,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$'+ str(i+1)),
            # https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
ax1.set(title=(filename + " - Packet $\Delta$t"),
        xlabel="t (s)",
        ylabel="$\Delta$t (ms)",
        ylim=[0,0.2],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(0.05))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')


# -----------------------------------
# plot TCP payload length - SMA 1 second
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
# plt.scatter(df2['tcp.time_relative'], 8*(df2['tcp.len'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        #plt.scatter(df['tcp.time_relative'], (df['tcp.len']), label='test ' + str(i))
        ax1.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            (df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(rolling_sma_window_array[i]).mean() / kbps_scale_factor),
            #label=files_array[i]
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
ax1.set(title=(filename + " - TCP payload size"),
        xlabel="t (s)",
        ylabel="TCP payload (KB)",
        ylim=[0,60],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(10))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='lower left')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')



'''
# -----------------------------------
# plot TCP segment length raw data
# -----------------------------------
plt.figure()
# plt.scatter(df2['tcp.time_relative'], 8*(df2['tcp.len'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.scatter(df['tcp.time_relative'], (df['tcp.len']),
                    #label=files_array[i]
                    label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1))
                    )
        #plt.plot(
        #    df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
        #    (df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(rolling_sma_window_array[i]).mean() / kbps_scale_factor),
        #    label=files_array[i]
        #)
plt.title(filename + " - TCP segment length ")
plt.xlabel("t (s)")
plt.grid('on')
plt.ylim(top=66000, bottom=0)
plt.xlim(right=RECONFIGURATION+2, left=RECONFIGURATION-2)
plt.ylabel("TCP Segment len (Bytes)")
plt.grid('on')
plt.legend(loc='lower left')
'''


# -----------------------------------
# plot Throughput as the ratio of the moving average of TCP segment length / dt
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
# create a new entry in the dataframe for the throughput with Moving Average
# https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            #8 * ((df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean()) /
            #    (df[df['tcp.time_relative'].notna()]['tcp.time_delta'].rolling(int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean())) / Gbs_scale_factor,
            8 * ((df[df['tcp.time_relative'].notna()]['tcp.len'].ewm(span=int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean()) /
              (df[df['tcp.time_relative'].notna()]['tcp.time_delta'].ewm(span=int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean())) / Gbs_scale_factor,
            #8 * ((df[df['tcp.time_relative'].notna()]['tcp.len'].ewm(alpha=ALPHA).mean()) /
            #     (df[df['tcp.time_relative'].notna()]['tcp.time_delta'].ewm(alpha=ALPHA).mean())) / Gbs_scale_factor,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )

ax1.set(title=(filename + r" - Throughput $\frac{TCP\ payload}{\Delta t}$ "),
        xlabel="t (s)",
        ylabel="Throughput (Gbps)",
        ylim=[BOTTOM_BW_AXIS,TOP_BW_AXIS],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(2))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='lower right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')


# -----------------------------------
# plot link unavailability based on discontinuities of TCP segment length data
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    df['link_unavailable'] = df['tcp.time_relative'].diff()
    if i not in remove_from_plot:
        # .diff returns the difference between previous row by default, useful to find all the discontinuities in time
        ax1.plot(df['tcp.time_relative'],
                    df['link_unavailable'],
                    label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
                    marker=markers[i % len(markers)],
                    markersize=MARKER_SIZE
                    )
ax1.set(title=(filename + " - Link unavailability"),
        xlabel="t (s)",
        ylabel="Link unavailability (s)",
        ylim=[0.02,1],
        xlim=[1.1,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(0.2))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(4))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')

# =============================================================================================================================
# Calculate packets sent, tcp.analysis.retransmissions and packet loss ratio

pkt_sent_array_series = []
pkt_retransmit_array_series = []
pkt_loss_ratio_array_series = []
link_unavailable_array_series = []
for i, df in enumerate(df_array):
    # now group tcp.analysis.retransmissions each second.
    # convert time index to integer
    # https://www.geeksforgeeks.org/convert-floats-to-integers-in-a-pandas-dataframe/
    print('calculating packet loss on df: ' + str(i))
    # drop na values on the column that we are going to convert to integer
    # https://stackoverflow.com/questions/13413590/how-to-drop-rows-of-pandas-dataframe-whose-value-in-a-certain-column-is-nan
    df = df[df['tcp.time_relative'].notna()]
    df['tcp.time_relative'] = df['tcp.time_relative'].astype(int)
    # print(df.keys())
    # print(df['tcp.analysis.retransmission'].unique())

    # convert tcp.analysis.retransmissions column to int
    # first element should be NaN for not tcp.analysis.retransmission
    df['tcp.analysis.retransmission'] = df['tcp.analysis.retransmission'].replace(df['tcp.analysis.retransmission'].unique()[0], 0)
    try:
        # second element should be a weird string of len 9, for tcp.analysis.retransmission
        df['tcp.analysis.retransmission'] = df['tcp.analysis.retransmission'].replace(df['tcp.analysis.retransmission'].unique()[1], 1)
    except:
        print('No tcp.analysis.retransmissions found')

    # count all the packets, no matter if lost or sent successfully.
    pkt_sent = df.groupby('tcp.time_relative')['tcp.analysis.retransmission'].count()
    #print('pkt sent mean: ' + str(pkt_sent.mean())) #for debugging purposes
    pkt_sent_array_series.append(pkt_sent)
    # add all the tcp.analysis.retransmissions per second, as a metric for packet loss
    pkt_retransmit = df.groupby('tcp.time_relative')['tcp.analysis.retransmission'].sum()
    #pkt_retransmit = df[df['tcp.analysis.retransmission']==1].groupby('tcp.time_relative')['tcp.analysis.retransmission'].count()
    pkt_retransmit_array_series.append(pkt_retransmit)
    # calculate the packet loss metric
    pkt_loss_ratio_array_series.append(100 * pkt_retransmit / pkt_sent)
    #pkt_loss_ratio_array_series.append(100 * pkt_retransmit / rolling_sma_window_array[i])


# Now plot the results.

'''
# -----------------------------------
# Plot sent packets per second
# -----------------------------------
plt.figure()
for i, pkt_sent in enumerate(pkt_sent_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_sent,
                 #label=files_array[i]
                 label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
                 marker=markers[i % len(markers)],
                 markevery=MARKER_EVERY_S ,
                 markersize=MARKER_SIZE
                 )
plt.title(filename + " - Packets sent")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")

plt.xlim(right=TEST_DURATION-1, left=0)
plt.grid('on')
plt.legend(loc='lower left')
'''


'''
# -----------------------------------
# Plot retransmitted packets per second
# -----------------------------------
plt.figure()
for i, pkt_retransmit in enumerate(pkt_retransmit_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_retransmit,
                 #label=files_array[i]
                 label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
                 marker=markers[i % len(markers)],
                 markevery=MARKER_EVERY_S,
                 markersize=MARKER_SIZE
                 )
plt.title(filename + " - Packets retransmitted")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")
plt.xlim(right=TEST_DURATION, left=0)
plt.grid('on')
plt.legend(loc='upper left')
'''

# -----------------------------------
# Plot packet loss metric
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        ax1.plot(pkt_loss_ratio,
                 #label=files_array[i]
                 label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
                 marker=markers[i % len(markers)],
                 markevery=MARKER_EVERY_S,
                 markersize=MARKER_SIZE
                 )
ax1.set(title=(filename + " - Packet loss ratio"),
        xlabel="t (s)",
        ylabel="%",
        ylim=[-0.1,10],
        xlim=[1.1,TEST_DURATION-1],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(2))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(4))
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))
else:
    ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')

'''
plt.figure()
#plot with stem
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        plt.stem(pkt_loss_ratio,
                 #label=files_array[i]
                 label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
                 #marker=markers[i % len(markers)],
                 #markevery=MARKER_EVERY_S,
                 #markersize=MARKER_SIZE
                 )
plt.title(filename + " - packet loss ratio")
plt.xlabel("t (s)")
plt.ylabel("%")
plt.ylim(top=2, bottom=-0.1)
plt.xlim(right=TEST_DURATION, left=0)
plt.grid('on')
plt.legend(loc='upper left')
'''

# -----------------------------------
# Plot packet loss as box plot
# -----------------------------------
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
df_loss=[[],[],[],[]]
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    #if i not in remove_from_plot:
    try:
        df_loss[0].append(pkt_loss_ratio[STEADY_INDEX])  # steady state
        if 'mbb' in files_array[i]:
            #single
            #df_loss[1].append(pkt_loss_ratio[5])  # make_before_break 1
            #df_loss[3].append(pkt_loss_ratio[15]) # make_before_break 2
            #df_loss[2].append(pkt_loss_ratio[10])  # optical reconfiguration
            #dual
            df_loss[1].append(max(pkt_loss_ratio[4],pkt_loss_ratio[5],pkt_loss_ratio[6]))  # make_before_break 1
            df_loss[3].append(max(pkt_loss_ratio[14],pkt_loss_ratio[15],pkt_loss_ratio[16])) # make_before_break 2
            df_loss[2].append(max(pkt_loss_ratio[9],pkt_loss_ratio[10],pkt_loss_ratio[11]))  # optical reconfiguration
        else:
            #if max(pkt_loss_ratio[9],pkt_loss_ratio[10],pkt_loss_ratio[11]) <20:
            df_loss[2].append(max(pkt_loss_ratio[9],pkt_loss_ratio[10],pkt_loss_ratio[11]))  # optical reconfiguration
    except:
        print('error calculating loss on df'+str(i))
#print('packet loss steady state len: '+str(len(df_loss[0])))
#print('packet loss optical switch reconfiguration t=10 len: ' + str(len(df_loss[2])))
if 'mbb' in files_array[0]:
    print('packet loss mbb 1 t=5 len: ' + str(len(df_loss[1])))
    print('packet loss mbb 2 t=15 len: ' + str(len(df_loss[3])))
    if BOXPLOT_MBB_SPACED:
        ax1.boxplot(df_loss)
        ax1.set_xticklabels(['steady', 't=5s', 't=10s', 't=15s'])
    else:
        ax1.boxplot([df_loss[0], df_loss[2]])
        ax1.set_xticklabels(['steady', 't=10s'])
    #plt.ylim(top=2, bottom=-0.1)
else:
    ax1.boxplot([df_loss[0], df_loss[2]])
    ax1.set_xticklabels(['steady', 't=10s'])
    #plt.ylim(top=20, bottom=-0.1)

print('Loss statistics: ')
print(pd.Series(df_loss[2]).describe())


ax1.set(title=(filename + " - Packet loss summary"),
        xlabel="t (s)",
        ylabel="%",
        ylim=[-0.1,10],
        #xlim=[1.1,TEST_DURATION-1],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
#ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(2))
# Change minor ticks to show every Major tick/N.
#ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(4))
ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')

# -----------------------------------
# Link unavailability as box plot
# -----------------------------------
df_link_unavailable=[[],[],[],[]]
fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
for i, df in enumerate(df_array):
    #if i not in remove_from_plot:
    df = df[df['tcp.time_relative'].notna()] # very important line. Otherwise an exception can be raised.
    df['tcp.time_relative'] = df['tcp.time_relative'].astype(int)
    # print(df[['tcp.time_relative', 'link_unavailable']]) #for debugging purposes
    df_link_unavailable[0].extend(df[(df['tcp.time_relative'] == STEADY_INDEX) & (df['link_unavailable']>0.006)]['link_unavailable'])  # steady state, bypass sampling rate

    if 'mbb' in files_array[i]:
        #single
        #df_link_unavailable[1].extend(df[(df['tcp.time_relative']==5)  & (df['link_unavailable']>0.03)]['link_unavailable'])  # make_before_break 1
        #df_link_unavailable[3].extend(df[(df['tcp.time_relative']==15) & (df['link_unavailable']>0.005) & (df['link_unavailable']<0.2)]['link_unavailable']) # make_before_break 2
        #df_link_unavailable[2].extend(df[(df['tcp.time_relative'] == 10) & (df['link_unavailable'] > 0.005)]['link_unavailable'])  # optical reconfiguration, bypass sampling rate
        #dual (bandwidth steering)
        try:
            df_link_unavailable[1].append(max(df[(df['tcp.time_relative']>=4)  & (df['tcp.time_relative']<=6)  & (df['link_unavailable']>0.03)]['link_unavailable']))  # make_before_break 1
        except:
            print('error on link unavailable mbb 1')
        try:
            df_link_unavailable[3].append(max(df[(df['tcp.time_relative']>=14) & (df['tcp.time_relative']<=16) & (df['link_unavailable']>0.005) & (df['link_unavailable']<0.2)]['link_unavailable'])) # make_before_break 2
        except:
            print('error on link unavailable mbb 2')
        try:
            df_link_unavailable[2].append(max(df[(df['tcp.time_relative']>=9) & (df['tcp.time_relative']<=11) & (df['link_unavailable'] > 0.005)]['link_unavailable']))  # optical reconfiguration, bypass sampling rate
        except:
            print('error on link unavailable ost 1')
    else:
        try:
            df_link_unavailable[2].append(max(df[(df['tcp.time_relative'] >=9) & (df['tcp.time_relative'] <= 11) & (df['link_unavailable'] > 0.006)]['link_unavailable']))  # optical reconfiguration, bypass sampling rate
        except:
            print ("df link unavailable error")
    #print(max(df[(df['tcp.time_relative'] >=9) & (df['tcp.time_relative'] <= 11) & (df['link_unavailable'] > 0.005)]['link_unavailable']))
    #df_link_unavailable[1].extend(df[(df['tcp.time_relative'] ==  5)]['link_unavailable'])  # make_before_break 1
    #df_link_unavailable[2].extend(df[(df['tcp.time_relative'] == 10)]['link_unavailable'])  # optical reconfiguration
    #df_link_unavailable[3].extend(df[(df['tcp.time_relative'] == 15)]['link_unavailable'])  # make_before_break 2

#print("link unavailable steady state len: "+ str(len(df_link_unavailable[0]))) #for debugging purposes
#print("link unavailable t=10 len: "+ str(len(df_link_unavailable[2]))) #for debugging purposes

if 'mbb' in files_array[0]:
    if BOXPLOT_MBB_SPACED:
        # t=5, t=10, t=15
        ax1.boxplot(df_link_unavailable)
        ax1.set_xticklabels(['steady', 't=5s', 't=10s', 't=15s'])
        #print("link unavailable t=5 len: " + str(len(df_link_unavailable[1])))  # for debugging purposes
        #print("link unavailable t=15 len: " + str(len(df_link_unavailable[3])))  # for debugging purposes
    else:
        # t=steady,t=10
        ax1.boxplot([df_link_unavailable[0], df_link_unavailable[2]])
        ax1.set_xticklabels(['steady', 't=10s'])


    #plt.ylim(top=1, bottom=-0.1)
else:
    ax1.boxplot([df_link_unavailable[0], df_link_unavailable[2]])
    ax1.set_xticklabels(['steady', 't=10s'])
    #plt.ylim(top=1, bottom=-0.1)
#plt.ylim(top=1, bottom=-0.05)

print('Link unavailable statistics: ')
print(pd.Series(df_link_unavailable[2]).describe())

ax1.set(title=(filename + " - Link unavailability summary"),
        ylabel="t (s)",
        ylim=[-0.1,1],
        #xlim=[1.1,TEST_DURATION-1],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
#ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(0.2))
# Change minor ticks to show every Major tick/N.
#ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(4))
#ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')


'''
# -----------------------------------
# Plot calculated throughput as packets sent * TCP Window size
# -----------------------------------
plt.figure()
for i, pkt_sent in enumerate(pkt_sent_array_series):
    if i not in remove_from_plot:
        #plt.plot(pkt_sent * TCP_WINDOW_SIZE * 8 / Gbs_scale_factor / 2, label=files_array[i])

        #updated formula: pkt_sent (packets/second) * effective TCP length (KBytes/packet) * 8 (bits/Byte) / Gbs_scale_factor
        plt.plot(pkt_sent * (df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(rolling_sma_window_array[i]).mean()).mean() * 8 / Gbs_scale_factor ,
                 #label=files_array[i]
                 label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
                 marker=markers[i % len(markers)],
                 markevery=MARKER_EVERY_S,
                 markersize=MARKER_SIZE
                 )
plt.title(filename + " - TCP Throughput as packets sent * TCP Window Size ")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=TOP_BW_AXIS, bottom=BOTTOM_BW_AXIS)
plt.xlim(right=TEST_DURATION-1, left=1)
plt.grid('on')
plt.legend(loc='lower left')
'''

'''
# -----------------------------------
# plot packet loss as the ratio of the retransmitted packets rolling / packets sent per second rolling
# -----------------------------------
plt.figure(figsize=(PIXEL_W*px, PIXEL_H*px))
# create a new entry in the dataframe for the throughput with Moving Average
# https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            df[df['tcp.time_relative'].notna()]['loss'],
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )

plt.title(filename + " - Packet loss (%) WND/RTT")
plt.xlabel("t (s)")
plt.ylabel("Packet loss (%)")
plt.ylim(top=10, bottom=-0.1)
plt.xlim(right=TEST_DURATION, left=1.1)
plt.grid('on')
#plt.legend(loc='upper right')
plt.legend(loc='lower right')
'''

'''
# -----------------------------------
# plot retransmitted packets rolling
# -----------------------------------
plt.figure(figsize=(PIXEL_W*px, PIXEL_H*px))
# create a new entry in the dataframe for the throughput with Moving Average
# https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            df[df['tcp.time_relative'].notna()]['tcp.analysis.retransmission'].rolling(int(rolling_sma_window_array[i] / ROLLING_FACTOR_LOSS)).sum(),
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )

plt.title(filename + " - Packet retransmission rolling")
plt.xlabel("t (s)")
plt.ylabel("Packet loss (%)")
plt.ylim(top=10, bottom=-0.1)
plt.xlim(right=TEST_DURATION, left=1.1)
plt.grid('on')
#plt.legend(loc='upper right')
plt.legend(loc='lower right')
'''


'''
# -----------------------------------
# plot sent packets rolling
# -----------------------------------
plt.figure(figsize=(PIXEL_W*px, PIXEL_H*px))
# create a new entry in the dataframe for the throughput with Moving Average
# https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'].rolling(int(rolling_sma_window_array[i] / ROLLING_FACTOR_LOSS)).count(),
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )

plt.title(filename + " - Packet sent rolling")
plt.xlabel("t (s)")
plt.ylabel("Packet loss (%)")
plt.ylim(top=10, bottom=-0.1)
plt.xlim(right=TEST_DURATION, left=1.1)
plt.grid('on')
#plt.legend(loc='upper right')
plt.legend(loc='lower right')
'''

'''
# -----------------------------------
# Plot packet loss as box plot - based on new packet loss SMA rolling sum of retransmissions / pkt sent metric
# -----------------------------------
plt.figure(figsize=(PIXEL_W*px, PIXEL_H*px))
df_loss=[[],[],[],[]]
for i, df in enumerate(df_array):
    #if i not in remove_from_plot:

    #try:
    df_loss[0].append(max(df[df['tcp.time_relative']< STEADY_INDEX]['loss']))  # steady state

    if 'mbb' in files_array[i]:
        df_loss[1].append(max(df[(df['tcp.time_relative']>=4) & (df['tcp.time_relative']<=6)]['loss']))  # make_before_break 1
        df_loss[3].append(max(df[(df['tcp.time_relative']>=14) & (df['tcp.time_relative']<=16)]['loss'])) # make_before_break 2
        df_loss[2].append(max(df[(df['tcp.time_relative']>=9) & (df['tcp.time_relative']<=12)]['loss']))  # optical reconfiguration
    else:
        #if max(pkt_loss_ratio[9],pkt_loss_ratio[10],pkt_loss_ratio[11]) <20:
        df_loss[2].append(max(df[(df['tcp.time_relative']>=9) & (df['tcp.time_relative']<=11)]['loss']))  # optical reconfiguration
    #except:
    #    print('error calculating loss on df'+str(i))
print('packet loss steady state len: '+str(len(df_loss[0])))
print('packet loss optical switch reconfiguration t=10 len: ' + str(len(df_loss[2])))
if 'mbb' in files_array[0]:
    print('packet loss mbb 1 t=5 len: ' + str(len(df_loss[1])))
    print('packet loss mbb 2 t=15 len: ' + str(len(df_loss[3])))
    if BOXPLOT_MBB_SPACED:
        plt.boxplot(df_loss)
        plt.xticks([1, 2, 3, 4], ['steady', 't=5s', 't=10s', 't=15s'])
    else:
        plt.boxplot([df_loss[0], df_loss[2]])
        plt.xticks([1, 2], ['steady', 't=10s'])
    #plt.ylim(top=2, bottom=-0.1)
else:
    plt.boxplot([df_loss[0], df_loss[2]])
    plt.xticks([1, 2], ['steady', 't=10s'])
    #plt.ylim(top=20, bottom=-0.1)
plt.ylim(top=2, bottom=-0.1)
plt.title(filename + " - packet loss ratio")
#plt.xlabel("t (s)")
plt.ylabel("%")
#plt.xlim(right=TEST_DURATION, left=0)
plt.grid('on')
#plt.legend(loc='upper left')
'''

plt.show()
