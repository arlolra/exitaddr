import json
import random
import functools

from zope.interface import implements
from txsocksx.http import SOCKS5Agent

from twisted.web.client import readBody
from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.error import ConnectionRefusedError

import txtorcon


class options(object):
    control_port = 45678
    socks_port = 45679
    first_hop = None
    num_exits = None
    exits = None
    initiate = 20


def norm(e):
    return "$"+e.strip().upper()


def cancelCanceler(canceler, result):
    if canceler.active():
        canceler.cancel()
    return result


class CantExitException(Exception):
    pass


class CDRSP(object):
    def __init__(self, circuit, dest, router, stream=None, port=None):
        self.circuit = circuit
        self.dest = dest
        self.router = router
        self.stream = stream
        self.port = port


class Attacher(txtorcon.CircuitListenerMixin, txtorcon.StreamListenerMixin):
    implements(txtorcon.IStreamAttacher)

    def __init__(self, state, exits, first_hop, exitaddr):
        self.state = state
        self.exits = exits
        self.first_hop = first_hop
        self.exitaddr = exitaddr
        self.circuits = {}
        self.ports = {}
        self.streams = {}
        self.finished = 0
        self.psd = 0
        self.fld = 0
        self.initiated = 0

    def start(self):
        e = self.exitaddr

        self.state.set_attacher(self, e.reactor)
        self.state.add_circuit_listener(self)
        self.state.add_stream_listener(self)

        for i in range(0, min(e.options.initiate, len(self.exits))):
            self.initiated += 1
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
            self.exitaddr.reactor.stop()
        elif self.initiated < len(self.exits):
            self.build_circuit(self.initiated)
            self.initiated += 1

    def stream_succeeded(self, stream):
        # print "successful stream:", stream.id, stream.target_host
        pass

    def stream_failed(self, stream, reason='', remote_reason='', **kw):
        # print 'stream %d failed because %s "%s"' % \
        # (stream.id, reason, remote_reason)
        pass

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
        e = self.exitaddr

        cdrsp = self.circuits[circuit.id]
        cdrsp.port = port
        self.ports[port] = cdrsp
        bindAddress = ("localhost", port)
        sockspoint = TCP4ClientEndpoint(e.reactor, "localhost",
                                        e.options.socks_port,
                                        bindAddress=bindAddress)
        agent = SOCKS5Agent(e.reactor, proxyEndpoint=sockspoint)
        d = agent.request("GET", "https://check.torproject.org/api/ip")  # port
        d.addCallback(readBody)
        d.addCallback(functools.partial(self.print_body, cdrsp))
        d.addErrback(functools.partial(self.failed, cdrsp.router))

        canceler = e.reactor.callLater(10, d.cancel)
        d.addBoth(functools.partial(cancelCanceler, canceler))

    def set_circuit(self, dest, router, circuit):
        cdrsp = CDRSP(circuit, dest, router)
        self.circuits[circuit.id] = cdrsp

    def circuit_built(self, circuit):
        c = self.circuits.get(circuit.id, None)

        if c is None:
            return  # ignore ... not our circuit

        d = txtorcon.util.available_tcp_port(self.exitaddr.reactor)
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


def can_exit(r, warn=False):
    dest = None
    if r.policy:
        for p in [443, 80, 6667]:
            if r.accepts_port(p):
                dest = p
                break
    if dest is None:
        # need full descriptors for these
        if warn:
            print "Can't exit to", r.unique_name
        pass
    return (dest, r)


def in_consensus(state, r):
    e = state.routers_by_hash.get(norm(r), None)
    if e is None:
        print "Not in consensus", r
    return e


class Exitaddr(object):
    def __init__(self, reactor, options):
        self.reactor = reactor
        self.options = options

    def start(self):
        connection = TCP4ClientEndpoint(self.reactor, "localhost",
                                        self.options.control_port)
        d = txtorcon.build_tor_connection(connection)
        d.addCallback(self.setup_success).addErrback(self.setup_failed)
        try:
            self.reactor.run()
        except KeyboardInterrupt:
            pass

    def setup_failed(self, failure):
        self.reactor.stop()
        if failure.check(ConnectionRefusedError):
            print "Connection refused. Is tor running?"
        elif not failure.check(CantExitException):
            print "Setup failed", failure

    def setup_success(self, state):
        global can_exit
        options = self.options

        if options.exits is not None:
            exits = map(lambda l: in_consensus(state, l), options.exits)
            exits = filter(lambda r: r is not None, exits)
            can_exit = functools.partial(can_exit, warn=True)
        else:
            exits = state.routers_by_hash.values()
        exits = filter(lambda r: "exit" in r.flags, exits)
        exits = map(can_exit, exits)
        exits = filter(lambda t: t[0] is not None, exits)

        if options.num_exits is not None:
            exits = random.sample(exits, options.num_exits)

        if len(exits) == 0:
            raise CantExitException

        if options.first_hop is None:
            # entry_guards will be empty with __DisablePredictedCircuits
            first_hop = random.choice(state.guards.values())
        else:
            first_hop = state.routers[norm(options.first_hop)]

        attacher = Attacher(state, exits, first_hop, self)
        attacher.start()