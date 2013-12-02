#!/usr/bin/python

import analyze_delays
import sys

if __name__ == "__main__" :
    if len(sys.argv) != 3:
        print "need filename and field"
        sys.exit(-1)

    ts, start = analyze_delays.get_taskstats(sys.argv[1])

    field = sys.argv[2]

    sort_key = lambda x : -(x.__dict__[field])


    v_tot = 0
    for t in sorted(ts, key = sort_key):
        if (sort_key(t) == 0):
            continue
        v = t.__dict__[field]
        v_tot += v
        print t.name, t.pid, v

    print v_tot
