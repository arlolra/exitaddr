#!/usr/bin/env python

import os
import sys
import json
import getopt
import functools

from twisted.internet import reactor

from common import Exitaddr, options


def usage():
    print """\
Usage: %(program_name)s --control_port [PORT]

  -h, --help            print this help message
  -c, --control_port    specify a tor control port (default "%(control_port)s")
  -s, --socks_port      specify a tor socks port (default "%(socks_port)s")
  -f, --first_hop       the 20-byte fingerprint of a tor relay to use as the\
                            first hop in the path
  -e, --exit            the fingerprint of a specific node to exit from
  -l, --list            path to a list of exits to test
  -n, --num_exits       sample n exits
""" % {
        "program_name": sys.argv[0],
        "control_port": options.control_port,
        "socks_port": options.socks_port
    }


def main():
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hc:s:f:n:e:l:", [
            "help",
            "control_port=",
            "socks_port=",
            "first_hop=",
            "num_exits=",
            "exit=",
            "list="
        ])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-c", "--control_port"):
            options.control_port = int(a)
        elif o in ("-s", "--socks_port"):
            options.socks_port = int(a)
        elif o in ("-f", "--first_hop"):
            options.first_hop = a
        elif o in ("-n", "--num_exits"):
            options.num_exits = int(a)
        elif o in ("-e", "--exit"):
            options.exits = [a]
        elif o in ("-l", "--list"):
            if not os.path.exists(a):
                print "List file doesn't exist"
                sys.exit(1)
            file = open(a, "r")
            options.exits = file.read().splitlines()
            file.close()
        else:
            assert False, "unhandled option"

    exitaddr = Exitaddr(reactor, options)
    exitaddr.start()


if __name__ == "__main__":
    main()
