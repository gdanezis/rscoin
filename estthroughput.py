import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from collections import defaultdict

import numpy as np
import pylab as P

import sys
from os.path import join
import re

from numpy import mean, std


def get_times(data):
    lst = re.findall("Commit OK \d+[.]\d+ \d+[.]\d+ \d+[.]\d+", data.read())
    lst = map(lambda x: (float(x.split()[4]), float(x.split()[4]) - float(x.split()[3])), lst)
    return lst


def process_recs(directory, fname):
    data = sorted(get_times(file(join(directory, fname))))
    
    recs = defaultdict(int)
    for tend, td in data:
        recs[int(tend)] += 1

    recs = list(sorted(recs.iteritems()))
    recs = [v for k, v in recs[1:-1]]

    print recs
    print "%10s\t% 6.4f\t% 6.4f" % (fname, mean(recs), std(recs))

    return recs, mean(recs), std(recs)


if __name__ == "__main__":
    directory = sys.argv[1]

    rec_issue = process_recs(directory, "issue-times.txt")
    rec_r1 = process_recs(directory, "r2-times.txt")
    rec_r2 = process_recs(directory, "r1-times.txt")

    # for k in sorted(rec_issue.keys() + rec_r1.keys() + rec_r2.keys()):
    # print k, rec_issue[k], rec_r1[k], rec_r2[k]

    # Totals:
    # print "Rate:", sum(recs.values()) / (max(recs) - min(recs))