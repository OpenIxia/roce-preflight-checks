"""Create a CDF plot

Specify onex_application_data.md file
Specify payload sizes

Usage:
   - Go to the results folder:
   - python3.10 ../../cdf.py --sizes 1073741824 test-1GB_all_to_all_application_2024-04-24_17-58-46.txt cdf_png_graph
"""
import argparse
import os
import statistics
import pandas
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import sys


def cdf_plot(sizes_to_data: dict, png_file: str):
    matplotlib.rcParams["figure.figsize"] = [10, 10]  # for square canvas
    matplotlib.rcParams["figure.subplot.left"] = 0.1
    matplotlib.rcParams["figure.subplot.bottom"] = 0.1
    matplotlib.rcParams["figure.subplot.right"] = 0.8
    matplotlib.rcParams["figure.subplot.top"] = 0.9
    legend = []
    ticks = []
    for size, data in sizes_to_data.items():
        size = int(size)
        x = np.sort(data)
        y = 1.0 * np.arange(len(data)) / (len(data) - 1)
        if min(data) - 1000 > 0:
            ticks.append(int(min(data) - 1000))
        ticks.append(int(statistics.mean(data)))
        ticks.append(int(max(data) + 1000))
        if size < 1024:
            legend.append(f"{size}B")
        else:
            legend.append(f"{size/(1024**2)}MB")
        plt.plot(x, y, marker="X")
    plt.xticks(ticks)
    plt.legend(legend, bbox_to_anchor=(1, 1), loc="upper left")
    plt.xlabel(f"queue pair completion time (us)")
    plt.ylabel("percentile")
    plt.title(f"CDF: Queue Pair Completion Time")
    plt.savefig(png_file)


# setup test arguments
parser = argparse.ArgumentParser()
parser.add_argument(
    'data_file',
    metavar='application_data.md',
    help="Input data",
)
parser.add_argument(
    'png_file',
    metavar='output.png',
    help="Output file",
)
parser.add_argument(
    "--sizes",
    help="Comma separated list of payload sizes to plot",
    required=True,
)
args = parser.parse_args()

sizes = args.sizes.split(",")

df: pandas.DataFrame = (
    pandas.read_table(
        args.data_file,
        sep="|",
        header=0,
        index_col=1,
        skipinitialspace=True,
    )
    .dropna(axis=1, how="all")
    .iloc[1:]
)
sizes_to_fct = {}
for size in sizes:
    fct_time = []
    for index in df.index:
        if df["size "][index].replace(" ", "") == size:
            fct_time.append(float(df["fct (us) "][index].replace(" ", "")))
    sizes_to_fct[size] = fct_time
cdf_plot(sizes_to_fct, args.png_file)
