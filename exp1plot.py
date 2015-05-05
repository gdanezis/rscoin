import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

import numpy as np
import pylab as P

import sys
from os.path import join
import re


directory = sys.argv[1]

d1 = file(join(directory, "issue-times.txt")).read()
issueT = np.array(map(float, re.findall("\d+[.]\d+", d1)))
r1T = map(float, re.findall("\d+[.]\d+", file(join(directory, "r1-times.txt")).read()))
r2T = map(float, re.findall("\d+[.]\d+", file(join(directory, "r2-times.txt")).read()))

print issueT

bins = np.arange(0,1, 0.05)
# the histogram of the data
n, bins, patches = plt.hist((issueT, r1T, r2T), bins, normed=1, alpha=0.75, label=["Issuing","Pay (Original)","Pay (Normal)"])

[p.set_hatch("/") for p in patches[0].patches]
[p.set_hatch("\\") for p in patches[1].patches]
[p.set_hatch("x") for p in patches[2].patches]


#patches[1].set_hatch("\\")
#patches[2].set_hatch("x")

#n, bins, patches2 = plt.hist(r1T, bins, normed=1, alpha=0.75, label="Pay (Original)")
#n, bins, patches3 = plt.hist(r2T, bins, normed=1, alpha=0.75, label="Pay (Normal)")


plt.xlabel('RSCoin Latency (sec)')
plt.ylabel('Probability density')
plt.title(r'Distribution of Issue & Pay Latency')
plt.axis([0, 1, 0, 10])
plt.grid(True)

first_legend = plt.legend(loc=1)

plt.show()