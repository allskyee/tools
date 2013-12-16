#!/usr/bin/python

import re
import sys
import pprint
import math
import copy

def int_comma_separated(n):
    r = []
    for i, c in enumerate(reversed(str(n))):
        if i and (not (i % 3)):
            r.insert(0, ',')
        r.insert(0, c)
    return ''.join(r)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "not enough parameters"
        sys.exit(0)

    rw = sys.argv[1]
    if rw != 'R' and rw != 'W':
        print "wrong param"
        sys.exit(-1)

    sectors =  {
        'Q' : {},
        'D' : {},
    }
    q_times = {}
    d_times = {}
    q2d_latencies = []
    d2c_latencies = []
    q2c_latencies = []
    for l in sys.stdin:
        spl = l.split()
        if spl == []:
            continue

        dev_id = spl[0]
        if len(dev_id.split(',')) != 2:
            continue #skip if not devid

        read_write = spl[6]
        if not rw in read_write:
            continue

        if not spl[7:]:
            continue

        blk_str = ' '.join(spl[7:])
        if '[' in blk_str:
            blk = blk_str.split(" [")[0]
            progname = re.search("\[(.*)\]", blk_str).group(0)
        else:
            blk = blk_str
            progname = ""

        if '+' in blk:
            sects = blk.split(" + ")[1]
        else:
            sects = '1'

        action = spl[5]

        #get latencies
        now = float(spl[3])
        if action == 'Q':
            q_times[blk] = (now, progname)
        elif action == 'D':
            if blk in q_times:
                then, progname = q_times[blk]
                q2d_latencies.append((then, now - then, blk, progname))
            d_times[blk] = (now, spl[-1])
        elif action == 'C':
            if blk in d_times:
                then, progname = d_times[blk]
                d2c_latencies.append((then, now - then, blk, progname))
                del d_times[blk]

            if blk in q_times:
                then, progname = q_times[blk]
                q2c_latencies.append((then, now - then, blk, progname))
                del q_times[blk]

        #get count per rq size
        if not action in sectors.keys():
            continue

        if not sects in sectors[action]:
            sectors[action][sects] = 0
        sectors[action][sects] += 1

    q2c_lat_tot = 0
    for q2c in q2c_latencies : 
        q2c_lat_tot += q2c[1]

    d2c_lat_tot = 0
    for d2c in d2c_latencies : 
        d2c_lat_tot += d2c[1]

    print q2c_lat_tot, d2c_lat_tot
    print len(q2c_latencies), len(d2c_latencies)

    for k, s in sectors.items() :
        sects_tot = 0
        for sz, cnt in s.items() : 
            sects_tot += (int(sz) * cnt)
        print k, sects_tot
