#!/usr/bin/env python

import sys
import json
import getopt
import random
import functools

import txtorcon

from twisted.internet import reactor, defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.web.client import readBody

from zope.interface import implements

from txsocksx.http import SOCKS5Agent

DEFAULT_CONTROL_PORT = 9051
DEFAULT_SOCKS_PORT = 9050


class options(object):
    control_port = DEFAULT_CONTROL_PORT
    socks_port = DEFAULT_SOCKS_PORT
    first_hop = None


def usage():
    print """\
Usage: %(program_name)s --control_port [PORT]

  -h, --help            print this help message
  -c, --control_port    specify a tor control port (default "%(control_port)s")
  -s, --socks_port      specify a tor socks port (default "%(socks_port)s")
  -f, --first_hop       the 20-byte fingerprint of a tor relay"
""" % {
        "program_name": sys.argv[0],
        "control_port": DEFAULT_CONTROL_PORT,
        "socks_port": DEFAULT_SOCKS_PORT
    }


class CDRSP(object):
    def __init__(self, circuit, dest, router, stream=None, port=None):
        self.circuit = circuit
        self.dest = dest
        self.router = router
        self.stream = stream
        self.port = port


class Attacher(txtorcon.CircuitListenerMixin, txtorcon.StreamListenerMixin):
    implements(txtorcon.IStreamAttacher)

    def __init__(self, state, exits, first_hop):
        self.state = state
        self.exits = exits  # random.sample(exits, 30)
        self.first_hop = first_hop
        self.circuits = {}
        self.ports = {}
        self.streams = {}
        self.finished = 0
        self.psd = 0
        self.fld = 0
        self.initiated = 20

    def start(self):
        for i in range(0, self.initiated):
            self.build_circuit(i)
    
    def build_circuit(self, i):
        dest, r = self.exits[i]
        path = [self.first_hop, r]
        d = self.state.build_circuit(path, using_guards=False)
        d.addCallback(functools.partial(self.set_circuit, dest, r))
        d.addErrback(functools.partial(self.failed, r))

    def stream_new(self, stream):
        # print "new stream:", stream.id, stream.target_host
        cdrsp = self.ports[stream.source_port]
        cdrsp.stream = stream
        self.streams[stream.id] = cdrsp

    def fini(self, psd=False):
        self.finished += 1
        if psd:
            self.psd += 1
        else:
            self.fld += 1
        if self.finished == len(self.exits):
            print ""
            print "passed", self.psd
            print "failed", self.fld
            print "total", self.finished
            reactor.stop()
        elif self.initiated < len(self.exits):
            self.build_circuit(self.initiated)
            self.initiated += 1

    def stream_succeeded(self, stream):
        # print "successful stream:", stream.id, stream.target_host
        pass

    def stream_failed(self, stream, reason='', remote_reason='', **kw):
        # print 'stream %d failed because %s "%s"' % \
        # (stream.id, reason, remote_reason)
        self.fini()

    def attach_stream(self, stream, circuits):
        cdrsp = self.streams[stream.id]
        return cdrsp.circuit

    def stream_attach(self, stream, circuit):
        # print "stream", stream.id, "attached to circuit", circuit.id
        # print self.circuits[circuit.id].router.unique_name
        # print "with path:", '->'.join(map(lambda x: x.location.countrycode,
        #                                   circuit.path))
        pass

    def print_body(self, cdrsp, body):
        j = json.loads(body)
        print cdrsp.router.unique_name[1:], j["IP"]
        self.fini(True)

    def set_port(self, circuit, port):
        cdrsp = self.circuits[circuit.id]
        cdrsp.port = port
        self.ports[port] = cdrsp
        bindAddress = ("localhost", port)
        sockspoint = TCP4ClientEndpoint(reactor, "localhost",
                                        options.socks_port,
                                        bindAddress=bindAddress)
        agent = SOCKS5Agent(reactor, proxyEndpoint=sockspoint)
        d = agent.request("GET", "https://check.torproject.org/api/ip")  # port
        d.addCallback(readBody)
        d.addCallback(functools.partial(self.print_body, cdrsp))
        d.addErrback(functools.partial(self.failed, cdrsp.router))

        canceler = reactor.callLater(5, d.cancel)
        def cancelCanceler(result):
            if canceler.active():
                canceler.cancel()
            return result
        d.addBoth(cancelCanceler)

    def set_circuit(self, dest, router, circuit):
        cdrsp = CDRSP(circuit, dest, router)
        self.circuits[circuit.id] = cdrsp

    def circuit_built(self, circuit):
        c = self.circuits.get(circuit.id, None)

        if c is None:
            return  # ignore ... not our circuit

        d = txtorcon.util.available_tcp_port(reactor)
        d.addCallback(functools.partial(self.set_port, circuit))
        d.addErrback(functools.partial(self.failed, c.router))

    def circuit_failed(self, circuit, **kw):
        c = self.circuits.get(circuit.id, None)

        if c is None:
            return  # ignore ... not our circuit
        
        # print 'Circuit %d failed "%s"' % (circuit.id, kw['REASON'])
        self.failed(c.router, None)

    def failed(self, r, err):
        print r.unique_name[1:], "failed"
        self.fini()


def doSetup(state):
    # print "Connected to a Tor version", state.protocol.version

    exits = filter(lambda r: "exit" in r.flags, state.routers_by_hash.values())
    def lam(r):
        dest = None
        if r.policy:
            for p in [443, 80, 6667]:
                if r.accepts_port(p):
                    dest = p
                    break
        if dest is None:
            # need full descriptors for these
            # print "Can't exit to", r.unique_name
            pass
        return (dest, r)
    exits = map(lam, exits)
    exits = filter(lambda t: t[0] is not None, exits)

    if options.first_hop is None:
        # entry_guards will be empty with __DisablePredictedCircuits
        first_hop = random.choice(state.guards.values())
    else:
        first_hop = state.routers[options.first_hop]

    attacher = Attacher(state, exits, first_hop)
    state.set_attacher(attacher, reactor)
    state.add_circuit_listener(attacher)
    state.add_stream_listener(attacher)

    attacher.start()


def setupFailed(arg):
    print "setup failed", arg
    reactor.stop()


def main():
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hc:s:f:", [
            "help",
            "control_port=",
            "socks_port=",
            "first_hop="
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
        else:
            assert False, "unhandled option"

    connection = TCP4ClientEndpoint(reactor, "localhost", options.control_port)
    d = txtorcon.build_tor_connection(connection)
    d.addCallback(doSetup).addErrback(setupFailed)
    reactor.run()


if __name__ == "__main__":
    main()
