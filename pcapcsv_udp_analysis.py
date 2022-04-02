'''
William Orozco
worozco at ucdavis dot edu
March 2022

Script to analyze L3 switching time of ToR

TO BE EXECUTED in any computer/server where the csv file is stored.
Save a parameter.json file, with the path of the csvfile.
{"datapath":<path>}
'''

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


# the following 2 lines can be replaced by only path=<INSERT_PATH_HERE>".
parameters = json.load(open('parameters.json'))
path = parameters["datapath_udp"]

files_array=[]
#for analyzing csv files in path
for file in os.listdir(path):
    # analyze only pcap files
    if (file.endswith(".csv")):# and ('v1' in file):
        files_array.append(file)
files_array.sort()
#files_array=files_array[0:10]


remove_from_plot=[]
#remove_from_plot.extend(list(range(0,10)))
remove_from_plot.extend(list(range(10,50)))

filename='EPS L3 Switching delay'
Gbs_scale_factor = 1000000000
ms_scale_factor = 1000
kbps_scale_factor = 1000
SPLIT_FILENAME_CHAR=')'

STEADY_INDEX = 2
LABEL_RIGHT_LIMIT = 2 # last element of filename standard to include in plot label
TEST_DURATION = 20
RECONFIGURATION = 10
XAXIS_LOCATOR = 2 # for xticklabels. 2 for test duration 20, and 10 for test duration 60

markers = ['>', '+', '.', ',', 'o', 'v', 'x', 'X', 'D', '|']
MARKER_SIZE = 10
MARKER_EVERY_S = 4 #add a marker to the time series every N seconds.
PIXEL_W=640 #for plot size
PIXEL_H=480
px = 1/plt.rcParams['figure.dpi'] #get dpi for pixel size setting
DPI = 300

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


print('-------plotting-------')
# -----------------------------------
# plot df['udp.time_delta'].diff(), vertical axis in us.
# -----------------------------------
#fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
fig1,ax1 = plt.subplots(figsize=(6,5),dpi=DPI)
for i, df in enumerate(df_array):
    if i not in remove_from_plot:
        ax1.plot(
            df[(df['udp.time_relative'].notna())]['udp.time_relative'],
            df[(df['udp.time_relative'].notna())]['udp.time_delta'].diff() * ms_scale_factor,
            label=('$\|$'.join(files_array[i].split(SPLIT_FILENAME_CHAR)[0:LABEL_RIGHT_LIMIT]) + '$\|$'+ str(i+1)),
            # https://www.geeksforgeeks.org/how-to-add-markers-to-a-graph-plot-in-matplotlib-with-python/
            marker=markers[i%len(markers)],
            markevery=MARKER_EVERY_S*int(len(df[(df['udp.time_relative'].notna())])/TEST_DURATION),
            markersize=MARKER_SIZE
        )
ax1.set(title=(filename + " - Packet $\Delta$t"),
        xlabel="Time [s]",
        ylabel="$\Delta$ t [ms]",
        ylim=[2.2,30],
        #xlim=[1.1,TEST_DURATION],
        xlim=[8.9,11.1],
        )
fig1.set_tight_layout(True)
# Change major ticks
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
ax1.xaxis.set_major_locator(MultipleLocator(1))
ax1.yaxis.set_major_locator(MultipleLocator(10))
# Change minor ticks to show every Major tick/N.
ax1.xaxis.set_minor_locator(AutoMinorLocator(10))
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



# -----------------------------------
# Link unavailability as box plot
# -----------------------------------
df_link_unavailable=[]
#fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
fig1,ax1 = plt.subplots(figsize=(6,5),dpi=DPI)
for i, df in enumerate(df_array):
    #df = df[df['udp.time_relative'].notna()]  # very important line. Otherwise an exception can be raised.

    try:
        df_link_unavailable.append(
            max(
            df[(df['udp.time_relative'] >=9) & (df['udp.time_relative'] <= 12) & (df['udp.time_relative'].notna())]
            ['udp.time_delta'].diff().fillna(0).values*ms_scale_factor
            )
        )
    except:
        print ("df link unavailable error")


# t=steady,t=10
#fig1.set_tight_layout(True)
ax1.boxplot(df_link_unavailable)
ax1.set_xticklabels(['t=10s'])

print('Link unavailable statistics: ')
print(pd.Series(df_link_unavailable).describe())

ax1.set(title=(filename + " - Link unavailability summary"),
        ylabel="Time [ms]",
        ylim=[0,30],
        #xlim=[1.1,TEST_DURATION-1],
        )
# Change major ticks to show every 20.
# https://stackoverflow.com/questions/24943991/change-grid-interval-and-specify-tick-labels-in-matplotlib
#ax1.xaxis.set_major_locator(MultipleLocator(XAXIS_LOCATOR))
ax1.yaxis.set_major_locator(MultipleLocator(10))
# Change minor ticks to show every Major tick/N.
#ax1.xaxis.set_minor_locator(AutoMinorLocator(5))
ax1.yaxis.set_minor_locator(AutoMinorLocator(5))
#ax1.legend(loc='upper right')
ax1.grid(which='major', color='#a3a3a3', linestyle='--')
ax1.grid(which='minor', color='#CCCCCC', linestyle=':')

plt.show()