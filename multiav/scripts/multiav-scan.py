#!/usr/bin/env python
import sys
from multiav.core import CMultiAV, AV_SPEED_ALL


# -----------------------------------------------------------------------
def main(path):
    multi_av = CMultiAV()
    ret = multi_av.scan(path, AV_SPEED_ALL)

    import pprint
    pprint.pprint(ret)


# -----------------------------------------------------------------------
def usage():
    print "Usage:", sys.argv[0], "<path>"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
    else:
        main(sys.argv[1])
