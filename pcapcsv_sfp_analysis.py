'''
William Orozco
worozco at ucdavis dot edu
March2022
Script to analyze sfp logs from pica8 ToR

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
path = parameters["datapath_sfp"]

files_array=[]
#for analyzing csv files in path
for file in os.listdir(path):
    # analyze only pcap files
    if (file.endswith(".csv")):# and ('v1' in file):
        files_array.append(file)
files_array.sort()
#files_array=files_array[0:10]

filename='SFP locking and switch polling delay'


PIXEL_W=640 #for plot size
PIXEL_H=480
px = 1/plt.rcParams['figure.dpi'] #get dpi for pixel size setting
DPI=300

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
# SFP delay as box plot
# -----------------------------------
#fig1,ax1 = plt.subplots(figsize=(PIXEL_W*px, PIXEL_H*px))
fig1,ax1 = plt.subplots(figsize=(5,4), dpi=DPI)

ax1.boxplot(df_array[0][df_array[0]['IS_SFP_EVENT']==1]['dt'])
ax1.set_xticklabels(['SFP delay'])

print('SFP delay statistics: ')
print(pd.Series(df_array[0][df_array[0]['IS_SFP_EVENT']==1]['dt']).describe())

ax1.set(title=(filename),
        ylabel="Time [s]",
        ylim=[0,1],
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

plt.show()