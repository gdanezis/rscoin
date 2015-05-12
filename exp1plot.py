import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

import numpy as np
import pylab as P

import sys
from os.path import join
import re



def get_times(data):
    lst = re.findall("Commit OK \d+[.]\d+ \d+[.]\d+ \d+[.]\d+", data.read())
    lst = map(lambda x: float(x.split()[2]), lst)
    return lst


if __name__ == "__main__":
    directory = sys.argv[1]

    issueT = get_times(file(join(directory, "issue-times.txt")))
    r1T = get_times(file(join(directory, "r1-times.txt")))
    r2T = get_times(file(join(directory, "r2-times.txt")))

    bins = np.arange(0,2, 0.075)
    # the histogram of the data
    # n, bins, patches = plt.hist((issueT, r1T, r2T), bins, normed=1, alpha=0.75, label=["Issuing","Pay (initial)","Pay (subsequent)"])
    n, bins, patches = plt.hist((r1T, r2T), bins, alpha=0.75, label=["Pay (run 1)","Pay (run 2)"], color=["b","r"])

    [p.set_hatch("/") for p in patches[0].patches]
    [p.set_hatch("\\") for p in patches[1].patches]
    #[p.set_hatch("x") for p in patches[2].patches]


    plt.xlabel('Latency (sec)')
    plt.ylabel('Number of transactions')
    # plt.title(r'RSCoin Issue & Pay Protocol Latency')
    print n
    plt.axis([0, 1.5, 0, max(max(n[0]), max(n[1])) + 50])
    plt.grid(True)

    first_legend = plt.legend(loc=1)

    plt.savefig(join(directory, "latency.pdf"))
    plt.close()