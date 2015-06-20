import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from collections import defaultdict

import numpy as np
import pylab as P

import sys
from os.path import join
import re

from estthroughput import process_recs

if __name__ == "__main__":
    X = []
    m_issue, v_issue = [], []
    m_r1, v_r1 = [], []
    m_r2, v_r2 = [], []

    for i in range(1, 11):
        X += [i]

        directory = "experiment3x%03d" % i
        cnt_issue, m, v = process_recs(directory, "issue-times.txt" )
        m_issue += [m]
        v_issue += [v]

        cnt_r1, m, s = process_recs(directory, "r1-times.txt")
        m_r1 += [m]
        v_r1 += [v]

        cnt_r2, m, s = process_recs(directory, "r2-times.txt")
        m_r2 += [m]
        v_r2 += [v]


    m_issue, v_issue, m_r1, v_r1, m_r2, v_r2 = map(np.array, (m_issue, v_issue, m_r1, v_r1, m_r2, v_r2))

    #plt.plot(X, m_issue, label="Issuing")
    #v = v_issue / (len(cnt_issue)**0.5)
    #plt.fill_between(x=X, y1=m_issue - v, y2=m_issue+v, alpha=0.2, color="b")

    plt.plot(X, m_r1, label="Pay (run 1)", color="b") #, linestyle="dashed")    
    v = v_r1 / (len(cnt_r1)**0.5)
    plt.fill_between(x=X, y1=m_r1 - v, y2=m_r1+v, alpha=0.2, color="b")

    plt.plot(X, m_r2, label="Pay (run 2)", linestyle="dashdot", color="r")
    v = v_r2 / (len(cnt_r2)**0.5)
    plt.fill_between(x=X, y1=m_r2 - v, y2=m_r2+v, alpha=0.2, color="r")


    plt.xlabel('Number of Servers')
    plt.ylabel('Transactions / sec')
    # plt.title(r'Transaction Throughput Scalability')
    plt.axis([1, 10, 0, 800])
    plt.grid(True)

    first_legend = plt.legend(loc="upper left")

    plt.savefig("Throughput.pdf")

    # plt.show()
    plt.close()
