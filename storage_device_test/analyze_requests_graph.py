#!/usr/bin/python

import re
import sys
import pprint
import math
import copy

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

def int_comma_separated(n):
    r = []
    for i, c in enumerate(reversed(str(n))):
        if i and (not (i % 3)):
            r.insert(0, ',')
        r.insert(0, c)
    return ''.join(r)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "not enough parameters"
        sys.exit(0)

    fn = sys.argv[1]
    rw = sys.argv[2]
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

    #pprint.pprint(sectors)

    #draw request size pie graph
    subplots = len(sectors.keys())
    axarr = []

    for i in range(1, subplots + 1):
        axarr.append(plt.subplot(2, subplots, i))
        axarr.append(plt.subplot(2, subplots, i + 2))

    proptease = fm.FontProperties()
    proptease.set_size('small')
    sectors_summary = {}
    for i, (k, v) in enumerate(sectors.items()):

        #rq
        items = sorted(v.items(), key = lambda x : -x[1])
        total_size = sum(map(lambda x : x[1], items))

        max_allowed = len(items)
        for ii, (kk, vv) in enumerate(items):
            if (vv / float(total_size) < 0.01):
                max_allowed = ii
                break

        if len(items) > max_allowed:
            s = sum(map(lambda x : x[1], items[max_allowed:]))
            items = items[:max_allowed]
            items.append(("other", s))

        labels = map(lambda x : x[0], items)
        fracs = map(lambda x : x[1], items)

        rqs = sum(fracs)
        title = rw + ' ' + k + ' ' + int_comma_separated(rqs) + " rq"
        #print "making " + title, i
        axarr[2 * i].set_title(title)
        patches, texts, autotexts = axarr[2 * i].pie(fracs, labels = labels, autopct="%1.1f%%")
        plt.setp(autotexts, fontproperties=proptease)
        plt.setp(texts, fontproperties=proptease)
        #axarr[2 * i].legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0., \
        #    prop={'size':'xx-small'})

        #in bytes
        items = sorted(map(lambda x : (x[0], long(x[0]) * x[1]), v.items()), \
            key = lambda x : -x[1])
        total_size = sum(map(lambda x : x[1], items))

        max_allowed = len(items)
        for ii, (kk, vv) in enumerate(items):
            if (vv / float(total_size) < 0.01):
                max_allowed = ii
                break

        if len(items) > max_allowed:
            s = sum(map(lambda x : x[1], items[max_allowed:]))
            items = items[:max_allowed]
            items.append(("other", s))

        labels = map(lambda x : x[0], items)
        fracs = map(lambda x : x[1] / float(total_size), items)

        io_bytes = total_size * 512
        title = rw + ' ' + k + ' ' + int_comma_separated(io_bytes) + ' Bytes'
        #print "making " + title
        axarr[2 * i + 1].set_title(title)
        patches, texts, autotexts = axarr[2 * i + 1].pie(fracs, labels = labels, autopct="%1.1f%%")
        plt.setp(autotexts, fontproperties=proptease)
        plt.setp(texts, fontproperties=proptease)
        #axarr[2 * i + 1].legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0., \
        #    prop={'size':'xx-small'})

        sectors_summary[k] = (rqs, io_bytes)

    plt.grid(True)
    plt.savefig(fn + "." + ("read" if rw == 'R' else "write") + "_rqs_pie.png", \
        bbox_inches = 'tight')

    #output rq latency summary
    with open(fn + '.' + ("read" if rw == 'R' else "write") + "_rqs_summary.dat", 'w') as f:
	f.write("==================== Request Statistics Summary ====================\n")
        for k, v in sectors.items():
            rqs, io_bytes = sectors_summary[k]
            f.write("%s : %d rqs, %d bytes, %f bytes/rq\n" % \
                (k, rqs, io_bytes, 0.0 if rqs == 0 else float(io_bytes) / rqs))
            for kk, vv in sorted(v.items(), key = lambda x : -x[1]):
                f.write(" %s %d\n" % (kk, vv))
        q2c_latencies = sorted(q2c_latencies, key = lambda x : x[1])
        def percentile(p):
            if len(q2c_latencies) < 1:
                return
            v = q2c_latencies[(len(q2c_latencies) * p) / 100 - 1]
            f.write(str(p) + " percentile : %0.4f %0.5f %s %s %s" % \
                (float(v[0]), float(v[1]), v[2].split(' + ')[0], v[2].split(' + ')[1], v[3]) + '\n')
    
        f.write("Percentiles (time, latency, sector)\n")
        percentile(80)
        percentile(90)
        percentile(95)
        percentile(99)
        percentile(100)
        
