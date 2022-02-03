'''
William Orozco
worozco at ucdavis dot edu
January 2021

Script to return RTT, throughput and packet loss based on a pcap file previously exported as csv with wireshark.

Plot multiple series in one plot, stateless approach with matplotlib
https://realpython.com/python-matplotlib-guide/

TO BE EXECUTED in any computer/server where the csv file is stored.
Required columns: Source, Destination, Stream index, Time since first frame in this TCP stream, Time, TCP Segment Len, Retransmission

'''
import math
import pandas as pd
import matplotlib.pyplot as plt
import json

parameters = json.load(open('parameters.json'))
path = parameters["datapath"]
files = []  # leave empty, for automatic file name appending
no_files = 10
filename = 'csv4gpython_'
extension = '.csv'
BANDWIDTH = 4
TOP_BW_AXIS = BANDWIDTH + 1
BOTTOM_BW_AXIS = BANDWIDTH - 1
desired_df_columns = ['Time since first frame in this TCP stream',
                      'Source',
                      'Destination',
                      'Stream index',
                      'Time',
                      'TCP Segment Len',
                      'Retransmission']

TCP_WINDOW_SIZE = 65535  # in Bytes
# Gbs_scale_factor = 1000000000 * math.sqrt(2) # for some reason, the calculated value is scaled by sqrt(2), so should divide by this.
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
def get_filenames(no_files=no_files, filename=filename, extension=extension, files_array=files):
    for i in range(1, no_files + 1):
        files_array.append(filename + str(i) + extension)
    return files_array


# read files and return the dataframe with the required columns
def read_files(files_array, path=path):
    df_array = []
    for i, filename in enumerate(files_array):
        # Read csv file and convert to pandas dataframe. Pull only relevant columns
        df_temp = pd.read_csv(path + filename, usecols=desired_df_columns)
        print('reading: ' + path + filename)
        df_array.append(df_temp)
    return df_array

def set_time_float_to_int(df_array, column='Time since first frame in this TCP stream'):
    df_out = []
    for df in df_array:
        df[column] = df[df[column].notna()][column].astype(int)
        df_out.append(df)
    print('converting time axis to int')
    return df_out

def find_pkt_sent(df_array,stream_index=1):
    pkt_sent_array = []
    for df in df_array:
        series=df[df['Stream index'] == stream_index].groupby('Time since first frame in this TCP stream')['Source'].count()
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
        df = df[(df['Source'] == '10.0.0.1')
                & (df['Destination'] == '10.0.0.4')
                & (df['Stream index'] == stream_index)]
        df_out.append(df)
    return df_out


'''
Processing section
'''
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
# plt.scatter(df2['Time since first frame in this TCP stream'], 1000*(df2['Time'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.plot(
            df[df['Time since first frame in this TCP stream'].notna()]['Time since first frame in this TCP stream'],
            df[df['Time since first frame in this TCP stream'].notna()]['Time'].rolling(rolling_sma_window_array[i]).mean() * ms_scale_factor,
            label=files_array[i]
        )
        #plt.plot(df['Time since first frame in this TCP stream'], df['Time'] * ms_scale_factor, label='test ' + str(i))
plt.title(filename + " - RTT")
plt.xlabel("t (s)")
plt.ylabel("RTT (ms)")
plt.ylim(top=0.2, bottom=0)
plt.xlim(right=60, left=1)
plt.grid('on')
plt.legend(loc='upper right')

# -----------------------------------
# plot TCP segment length - SMA 1 second
# -----------------------------------
plt.figure()
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        #plt.scatter(df['Time since first frame in this TCP stream'], (df['TCP Segment Len']), label='test ' + str(i))
        plt.plot(
            df[df['Time since first frame in this TCP stream'].notna()]['Time since first frame in this TCP stream'],
            (df[df['Time since first frame in this TCP stream'].notna()]['TCP Segment Len'].rolling(rolling_sma_window_array[i]).mean() / kbps_scale_factor),
            label=files_array[i]
        )
plt.title(filename + " - TCP segment length")
plt.xlabel("t (s)")
plt.grid('on')
plt.ylim(top=60, bottom=0)
plt.xlim(right=60, left=0)
plt.ylabel("TCP Segment len (KBytes)")
plt.grid('on')
plt.legend(loc='lower left')


# -----------------------------------
# plot TCP segment length raw data
# -----------------------------------
plt.figure()
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len'].rolling(1000).mean()))
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        plt.scatter(df['Time since first frame in this TCP stream'], (df['TCP Segment Len']), label='test ' + str(i))
        #plt.plot(
        #    df[df['Time since first frame in this TCP stream'].notna()]['Time since first frame in this TCP stream'],
        #    (df[df['Time since first frame in this TCP stream'].notna()]['TCP Segment Len'].rolling(rolling_sma_window_array[i]).mean() / kbps_scale_factor),
        #    label=files_array[i]
        #)
plt.title(filename + " - TCP segment length ")
plt.xlabel("t (s)")
plt.grid('on')
plt.ylim(top=60, bottom=0)
plt.xlim(right=60, left=0)
plt.ylabel("TCP Segment len (KBytes)")
plt.grid('on')
plt.legend(loc='lower left')
# -----------------------------------
# plot Throughput as the ratio of the moving average of TCP segment length / RTT
# -----------------------------------
plt.figure()
# create a new entry in the dataframe for the throughput with Moving Average
# https://www.geeksforgeeks.org/how-to-calculate-moving-average-in-a-pandas-dataframe/
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        # plt.scatter(df2['Time since first frame in this TCP stream'], df2['Throughput'])
        # plt.plot(df['Time since first frame in this TCP stream'], 8 * ((df['TCP Segment Len'].rolling(10000).mean()) / (
        #    df['Time'].rolling(10000).mean())) / Gbs_scale_factor, label='test ' + str(i))
        # plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['TCP Segment Len']/(df2['Time']).rolling(1000).mean() / 1024000))
        plt.plot(
            df[df['Time since first frame in this TCP stream'].notna()]['Time since first frame in this TCP stream'],
            8 * ((df[df['Time since first frame in this TCP stream'].notna()]['TCP Segment Len'].rolling(rolling_sma_window_array[i]).mean()) /
                (df[df['Time since first frame in this TCP stream'].notna()]['Time'].rolling(rolling_sma_window_array[i]).mean())) / Gbs_scale_factor,
            label=files_array[i]
        )

plt.title(filename + " - Throughput (Gbps) WND/RTT")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=TOP_BW_AXIS, bottom=BOTTOM_BW_AXIS)
plt.xlim(right=60, left=1)
plt.grid('on')
plt.legend(loc='upper right')

# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Length'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['Length'].rolling(1000).mean())/(df2['Time'].rolling(1000).mean())/1000000)
# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Length'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], df2['Time'].rolling(1000).mean())
# plt.scatter(df2['Time since first frame in this TCP stream'], 8*(df2['Length'].rolling(1000).mean())/(df2['Time'].rolling(1000).mean())/1000000)


# =============================================================================================================================
# Calculate packets sent, retransmissions and packet loss ratio

pkt_sent_array_series = []
pkt_retransmit_array_series = []
pkt_loss_ratio_array_series = []
for i, df in enumerate(df_array):
    # now group retransmissions each second.
    # convert time index to integer
    # https://www.geeksforgeeks.org/convert-floats-to-integers-in-a-pandas-dataframe/
    print('working on df: ' + str(i))
    # df = df.dropna()

    # drop na values on the column that we are going to convert to integer
    # https: // stackoverflow.com / questions / 13413590 / how - to - drop - rows - of - pandas - dataframe - whose - value - in -a - certain - column - is -nan
    df = df[df['Time since first frame in this TCP stream'].notna()]
    df['Time since first frame in this TCP stream'] = df['Time since first frame in this TCP stream'].astype(int)
    # print(df.keys())
    # print(df['Retransmission'].unique())

    # convert retransmissions column to int
    # first element should be NaN for not retransmission
    df['Retransmission'] = df['Retransmission'].replace(df['Retransmission'].unique()[0], 0)
    try:
        # second element should be a weird string of len 9, for retransmission
        df['Retransmission'] = df['Retransmission'].replace(df['Retransmission'].unique()[1], 1)
    except:
        print('No retransmissions found')

    # count all the packets, no matter if lost or sent successfully.
    pkt_sent = df.groupby('Time since first frame in this TCP stream')['Retransmission'].count()
    print('pkt sent mean: ' + str(pkt_sent.mean()))
    pkt_sent_array_series.append(pkt_sent)
    # add all the retransmissions per second, as a metric for packet loss
    pkt_retransmit = df.groupby('Time since first frame in this TCP stream')['Retransmission'].sum()
    pkt_retransmit_array_series.append(pkt_retransmit)
    # calculate the packet loss metric
    pkt_loss_ratio_array_series.append(100 * pkt_retransmit / pkt_sent)

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

plt.xlim(right=59, left=0)
plt.grid('on')
plt.legend(loc='lower left')

# -----------------------------------
# Plot retransmitted packets per second
# -----------------------------------
plt.figure()
for i, pkt_retransmit in enumerate(pkt_retransmit_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_retransmit, label=files_array[i])
plt.title(filename + " - Packets retransmitted")
plt.xlabel("t (s)")
plt.ylabel("Packets / second")
plt.xlim(right=60, left=0)
plt.grid('on')
plt.legend(loc='upper left')

# -----------------------------------
# Plot packet loss metric
# -----------------------------------
plt.figure()
for i, pkt_loss_ratio in enumerate(pkt_loss_ratio_array_series):
    if i not in remove_from_plot:
        plt.plot(pkt_loss_ratio, label=files_array[i])
plt.title(filename + " - packet loss ratio")
plt.xlabel("t (s)")
plt.ylabel("%")
plt.ylim(top=2, bottom=-0.1)
plt.xlim(right=60, left=0)
plt.grid('on')
plt.legend(loc='upper left')

# -----------------------------------
# Plot calculated throughput as packets sent * TCP Window size
# -----------------------------------
plt.figure()
for i, pkt_sent in enumerate(pkt_sent_array_series):
    if i not in remove_from_plot:
        #plt.plot(pkt_sent * TCP_WINDOW_SIZE * 8 / Gbs_scale_factor / 2, label=files_array[i])

        #updated formula: pkt_sent (packets/second) * effective TCP length (KBytes/packet) * 8 (bits/Byte) / Gbs_scale_factor
        plt.plot(pkt_sent * (df[df['Time since first frame in this TCP stream'].notna()]['TCP Segment Len'].rolling(rolling_sma_window_array[i]).mean()).mean() * 8 / Gbs_scale_factor , label=files_array[i])
plt.title(filename + " - TCP Throughput as packets sent * TCP Window Size ")
plt.xlabel("t (s)")
plt.ylabel("Throughput (Gbps)")
plt.ylim(top=TOP_BW_AXIS, bottom=BOTTOM_BW_AXIS)
plt.xlim(right=59, left=1)
plt.grid('on')
plt.legend(loc='lower left')

plt.show()
