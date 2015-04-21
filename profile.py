## Process profiling traces
#  exctracted with: python -m cProfile -o profile $(which py.test)
# python -m cProfile -o profile c:\Python27\Scripts\py.test-2.7-script.py

import pstats
p = pstats.Stats('profile')
p.sort_stats("tottime")
p.print_stats()