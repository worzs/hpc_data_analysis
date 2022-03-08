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
import matplotlib.pyplot as plt
import json
import os

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
#files_array=files_array[0:3]

#parameters for automatic filename generation
no_files = 1
#the following two parameters help when more than 1 experiment is going to be analyzed at the same bandwidth.
#filename = 'csv4gpython_'
filename = ''
extension = '.csv'

LABEL_RIGHT_LIMIT = 3 # last element of filename standard to include in plot label
TEST_DURATION=20
RECONFIGURATION = 10

markers = ['>', '+', '.', ',', 'o', 'v', 'x', 'X', 'D', '|']
MARKER_SIZE=10
MARKER_EVERY_S = 4 #add a marker to the time series every N seconds.


BANDWIDTH = 10
TOP_BW_AXIS = 10
BOTTOM_BW_AXIS = 0
desired_df_columns = ['tcp.time_relative',
                      'ip.src',
                      'ip.dst',
                      'tcp.stream',
                      'tcp.time_delta',
                      'tcp.len',
                      'tcp.window_size',
                      'tcp.analysis.retransmission']

#factors for modifying the rolling window size of moving average
ROLLING_FACTOR=2 # used for calculating average throughput. rolling 1 second means SMA 1, rolling N means SMA 1/N seconds
ALPHA=0.5
ROLLING_FACTOR_RTT=2 # used for calculating average RTT. rolling 1 second means SMA 1, rolling N means SMA 1/N seconds

TCP_WINDOW_SIZE = 65535  # in Bytes
Gbs_scale_factor = 1000000000
ms_scale_factor = 1000
kbps_scale_factor = 1000
stream_index = 1

#remove_from_plot = [2,5,6]
remove_from_plot = []



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

def find_pkt_sent(df_array,stream_index=1):
    pkt_sent_array = []
    for df in df_array:
        series=df[df['tcp.stream'] == stream_index].groupby('tcp.time_relative')['ip.src'].count()
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


# filter traffic sent from vm1 to vm4, drop the rest. currently not used.
def filter_packets_vm1_vm4(df_array):
    df_out = []
    for df in df_array:
        df = df[(df['ip.src'] == '10.0.0.1')
                & (df['ip.dst'] == '10.0.0.4')
                & (df['tcp.stream'] == stream_index)]
        df_out.append(df)
    return df_out


'''
Processing section
'''
if len(files_array)==0:
    files_array = get_filenames()
df_array = read_files(files_array)
df_array_time_int = set_time_float_to_int(df_array)
pkt_sent_array = find_pkt_sent(df_array_time_int)
rolling_sma_window_array = find_rolling_sma_window(pkt_sent_array)
df_array = read_files(files_array)
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
# plt.scatter(df2['tcp.time_relative'], 1000*(df2['tcp.time_delta'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            df[df['tcp.time_relative'].notna()]['tcp.time_delta'].rolling(int(rolling_sma_window_array[i]/ROLLING_FACTOR_RTT)).mean() * ms_scale_factor,
            #label=files_array[i]
            label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|'+ str(i+1)),
            #https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
        #plt.plot(df['tcp.time_relative'], df['tcp.time_delta'] * ms_scale_factor, label='test ' + str(i))
plt.title(filename + " - RTT")
plt.xlabel("t (s)")
plt.ylabel("RTT (ms)")
plt.ylim(top=0.2, bottom=0)
plt.xlim(right=TEST_DURATION, left=1)
plt.grid('on')
plt.legend(loc='upper right')

# -----------------------------------
# plot TCP segment length - SMA 1 second
# -----------------------------------
plt.figure()
# plt.scatter(df2['tcp.time_relative'], 8*(df2['tcp.len'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        #plt.scatter(df['tcp.time_relative'], (df['tcp.len']), label='test ' + str(i))
        plt.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            (df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(rolling_sma_window_array[i]).mean() / kbps_scale_factor),
            #label=files_array[i]
            label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )
plt.title(filename + " - TCP segment length")
plt.xlabel("t (s)")
plt.grid('on')
plt.ylim(top=60, bottom=0)
plt.xlim(right=TEST_DURATION, left=1)
plt.ylabel("TCP Segment len (KBytes)")
plt.grid('on')
plt.legend(loc='lower left')

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
                    label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1))
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
# plot link unavailability based on discontinuities of TCP segment length data
# -----------------------------------
plt.figure()
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        df['link_unavailable'] = df['tcp.time_relative'].diff()
        #.diff returns the difference between previous row by default, useful to find all the discontinuities in time
        plt.plot(df['tcp.time_relative'],
                    df['link_unavailable'],
                    label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
                    marker=markers[i % len(markers)],
                    markersize=MARKER_SIZE
                    )
plt.title(filename + " - Link unavailability ")
plt.xlabel("t (s)")
plt.grid('on')
plt.ylim(top=0.5, bottom=0)
plt.xlim(right=TEST_DURATION, left=1)
plt.ylabel("Link unavailability (s)")
plt.grid('on')
plt.legend(loc='upper right')

'''
# -----------------------------------
# plot TCP window size raw data
# -----------------------------------
plt.figure()
# plt.scatter(df2['tcp.time_relative'], 8*(df2['tcp.len'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.scatter(df['tcp.time_relative'], (df['tcp.window_size']),
                    #label=files_array[i]
                    label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|'+ str(i+1))
                    )
        #plt.plot(
        #    df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
        #    (df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(rolling_sma_window_array[i]).mean() / kbps_scale_factor),
        #    label=files_array[i]
        #)
plt.title(filename + " - TCP window size ")
plt.xlabel("t (s)")
plte.grid('on')
plt.ylim(top=66000, bottom=0)
plt.xlim(right=RECONFIGURATION+2, left=RECONFIGURATION-2)
plt.ylabel("TCP window size (Bytes)")
plt.grid('on')
plt.legend(loc='lower left')
'''

# -----------------------------------
# plot Throughput as the ratio of the moving average of TCP segment length / RTT
# -----------------------------------
plt.figure()
# create a new entry in the dataframe for the throughput with Moving Average
# https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        # plt.scatter(df2['tcp.time_relative'], df2['Throughput'])
        # plt.plot(df['tcp.time_relative'], 8 * ((df['tcp.len'].rolling(10000).mean()) / (
        #    df['tcp.time_delta'].rolling(10000).mean())) / Gbs_scale_factor, label='test ' + str(i))
        # plt.scatter(df2['tcp.time_relative'], 8*(df2['tcp.len']/(df2['tcp.time_delta']).rolling(1000).mean() / 1024000))
        plt.plot(
            df[df['tcp.time_relative'].notna()]['tcp.time_relative'],
            #8 * ((df[df['tcp.time_relative'].notna()]['tcp.len'].rolling(int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean()) /
            #    (df[df['tcp.time_relative'].notna()]['tcp.time_delta'].rolling(int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean())) / Gbs_scale_factor,
            8 * ((df[df['tcp.time_relative'].notna()]['tcp.len'].ewm(span=int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean()) /
              (df[df['tcp.time_relative'].notna()]['tcp.time_delta'].ewm(span=int(rolling_sma_window_array[i]/ROLLING_FACTOR)).mean())) / Gbs_scale_factor,
            #8 * ((df[df['tcp.time_relative'].notna()]['tcp.len'].ewm(alpha=ALPHA).mean()) /
            #     (df[df['tcp.time_relative'].notna()]['tcp.time_delta'].ewm(alpha=ALPHA).mean())) / Gbs_scale_factor,

            #label=files_array[i]
            label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
            marker=markers[i % len(markers)],
            markevery=MARKER_EVERY_S * rolling_sma_window_array[i],
            markersize=MARKER_SIZE
        )

plt.title(filename + " - Throughput (Gbps) WND/RTT")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=TOP_BW_AXIS, bottom=BOTTOM_BW_AXIS)
plt.xlim(right=TEST_DURATION, left=1)
plt.grid('on')
#plt.legend(loc='upper right')
plt.legend(loc='lower right')


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
    print('working on df: ' + str(i))
    # df = df.dropna()

    # drop na values on the column that we are going to convert to integer
    # https: // stackoverflow.com / questions / 13413590 / how - to - drop - rows - of - pandas - dataframe - whose - value - in -a - certain - column - is -nan
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
    print('pkt sent mean: ' + str(pkt_sent.mean()))
    pkt_sent_array_series.append(pkt_sent)
    # add all the tcp.analysis.retransmissions per second, as a metric for packet loss
    pkt_retransmit = df.groupby('tcp.time_relative')['tcp.analysis.retransmission'].sum()
    pkt_retransmit_array_series.append(pkt_retransmit)
    # calculate the packet loss metric
    pkt_loss_ratio_array_series.append(100 * pkt_retransmit / pkt_sent)


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
                 label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
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
                 label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
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
plt.figure()
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_loss_ratio,
                 #label=files_array[i]
                 label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
                 marker=markers[i % len(markers)],
                 markevery=MARKER_EVERY_S,
                 markersize=MARKER_SIZE
                 )
plt.title(filename + " - packet loss ratio")
plt.xlabel("t (s)")
plt.ylabel("%")
plt.ylim(top=2, bottom=-0.1)
plt.xlim(right=TEST_DURATION, left=0)
plt.grid('on')
plt.legend(loc='upper left')

'''
plt.figure()
#plot with stem
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        plt.stem(pkt_loss_ratio,
                 #label=files_array[i]
                 label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
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
plt.figure()
df_loss=[[],[],[]]
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        df_loss[0].append(pkt_loss_ratio[5])  # make_before_break 1
        df_loss[1].append(pkt_loss_ratio[10]) # optical reconfiguration
        df_loss[2].append(pkt_loss_ratio[15]) # make_before_break 2
print(df_loss)
plt.boxplot(df_loss)
plt.title(filename + " - packet loss ratio")
#plt.xlabel("t (s)")
plt.ylabel("%")
plt.ylim(top=2, bottom=-0.1)
#plt.xlim(right=TEST_DURATION, left=0)
plt.grid('on')
#plt.legend(loc='upper left')


# -----------------------------------
# Link unavailability as box plot
# -----------------------------------
df_link_unavailable=[[],[],[]]
plt.figure()
for i, df in enumerate(df_array):
    if i not in remove_from_plot:

        df['tcp.time_relative'] = df['tcp.time_relative'].astype(int)
        #print(df[['tcp.time_relative', 'link_unavailable']])
        df_link_unavailable[0].extend(df[(df['tcp.time_relative']==5)  & (df['link_unavailable']>0.02)]['link_unavailable'])  # make_before_break 1
        df_link_unavailable[1].extend(df[(df['tcp.time_relative']==10) & (df['link_unavailable']>0.005)]['link_unavailable']) # optical reconfiguration
        df_link_unavailable[2].extend(df[(df['tcp.time_relative']==15) & (df['link_unavailable']>0.005)]['link_unavailable']) # make_before_break 2
print(df_link_unavailable)
plt.boxplot(df_link_unavailable)
plt.title(filename + " - link unavailability")
#plt.xlabel("t (s)")
plt.ylabel(" t(s)")
plt.ylim(top=0.5, bottom=-0.1)
#plt.xlim(right=TEST_DURATION, left=0)
plt.grid('on')
#plt.legend(loc='upper left')


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
                 label=('|'.join(files_array[i].split('|')[0:LABEL_RIGHT_LIMIT]) + '|' + str(i+1)),
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


plt.show()
