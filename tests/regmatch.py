#!/usr/bin/env python3

import re
import sys

rdata = '\A' + open(sys.argv[1]).read() + '\Z'
r = re.compile(rdata, re.MULTILINE | re.DOTALL)

data = sys.stdin.read()
m= r.findall(data)
if not m:
    #print("%s doesn't match %s" % (data, rdata))
    #print("NOO")
    sys.exit(1)
else:
    #print(m)
    pass
