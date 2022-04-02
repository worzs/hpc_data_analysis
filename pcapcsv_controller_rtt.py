import pandas as pd
import matplotlib
matplotlib.use('Qt5Agg', force=True) #fix for use qt5agg backend for matplotlib. Use $pip install pyqt5
# https://python-graph-gallery.com/custom-fonts-in-matplotlib
matplotlib.rcParams['font.family'] = 'cmr10' #for labels, titles, and other text
matplotlib.rcParams['mathtext.fontset'] = 'cm'
matplotlib.rcParams['font.size'] = 11
import matplotlib.pyplot as plt
from matplotlib.ticker import (AutoMinorLocator, MultipleLocator)
import json
import os

markers = ['>', '+', '.', ',', 'o', 'v', 'x', 'X', 'D', '|']
MARKER_SIZE = 10
MARKER_EVERY_S = 4 #add a marker to the time series every N seconds.
PIXEL_W=640 #for plot size
PIXEL_H=480
px = 1/plt.rcParams['figure.dpi'] #get dpi for pixel size setting
TEST_DURATION = 5
DPI = 300

# the following 2 lines can be replaced by only path=<INSERT_PATH_HERE>".
parameters = json.load(open('parameters.json'))
path = parameters["datapath_controller_rtt"]

files_array=[]
#for analyzing csv files in path
for file in os.listdir(path):
    # analyze only pcap files
    if (file.endswith(".csv")):# and ('v1' in file):
        files_array.append(file)
files_array.sort()
#files_array=files_array[0:10]

filename='Orchestrator to controller ACK RTT'

# read files and return the dataframe with the required columns
def read_files(files_array, path=path):
    df_array = []
    for i, filename in enumerate(files_array):
        # Read csv file and convert to pandas dataframe. Pull only relevant columns
        try:
            df_temp = pd.read_csv(path + filename, encoding="ISO-8859-1") #fix for pandas 1.4
            print('reading: ' + path + filename)
            df_array.append(df_temp)
        except:
            print('error reading: ' + path + filename)
    return df_array
df_array=read_files(files_array)


#identify tcp stream with wireshark...
#remove outliers
#fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
fig1,ax1 = plt.subplots(figsize=(5,4),dpi=300)
ax1.plot(
	df_array[0][(df_array[0]['tcp.stream']==1)&(df_array[0]['tcp.analysis.ack_rtt']<=0.001)]['tcp.time_relative'],
	df_array[0][(df_array[0]['tcp.stream']==1)&(df_array[0]['tcp.analysis.ack_rtt']<=0.001)]['tcp.analysis.ack_rtt'].ewm(span=10).mean() *1000
	#label=('$\|$'.join(filename.split(')')[0:1]) + '$\|$'),
)
#print("rolling sma: " + str(rolling_sma_window_array[i]))
#print("len rtt_ack array: " + str(len(df[(df['tcp.time_relative'].notna())
#               & (df['tcp.analysis.ack_rtt'].notna())
#               & (df['tcp.srcport']==6633)])))
ax1.set(title=("Orchestrator to controller ACK RTT"),
        xlabel="Time [s]",
        ylabel="RTT [ms]",
        ylim=[0,1],
        xlim=[0,TEST_DURATION],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(1))
ax1.yaxis.set_major_locator(MultipleLocator(0.2))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(2))
# adjust figure width and legend position
if len(files_array)>2:
    # Shrink current axis by 20%
    fig1.set_figwidth(1.3 * PIXEL_W * px)
    box = ax1.get_position()
    ax1.set_position([box.x0, box.y0, box.width * 0.7, box.height])
    ax1.legend(loc='center left', bbox_to_anchor=(1, 0.5))

#else:
    #ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')
#enable tightlayout to figure before saving.
plt.show()