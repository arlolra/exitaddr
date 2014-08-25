import json
import random
import functools

from zope.interface import implements

from txsocksx.http import SOCKS5Agent
from txsocksx import errors as tserrors

from twisted.python import log
from twisted.web.client import readBody
from twisted.web._newclient import ResponseNeverReceived
from twisted.internet import defer
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.internet.error import ConnectionRefusedError

from stem.control import Controller

import txtorcon

#CHECK_IP = "38.229.72.22"
CHECK_IP = "107.170.31.200"  # ipinfo.io support http(s)

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
        self.results = {}
        self.finished = 0
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
        d.addErrback(functools.partial(self.failed, r, "build_circuit"))
        d.addErrback(log.err)

    def stream_new(self, stream):
        # print "new stream:", stream.id, stream.target_host
        cdrsp = self.ports.get(stream.source_port, None)
        if cdrsp is None:
            return  # ignore ... not our stream
        cdrsp.stream = stream
        self.streams[stream.id] = cdrsp

    def report(self, router, passed, ip=None):
        e = self.exitaddr
        self.finished += 1
        result = self.results[router.id_hex[1:]] = (router, ip)

        try:
            if passed:
                e.passed(result)
            else:
                e.failed(result)
        except Exception as err:
            log.err(err)

        if self.finished == len(self.exits):
            e.finished(self.results)
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
        cdrsp = self.streams.get(stream.id, None)
        if cdrsp is None:
            return  # ignore ... not our stream
        return cdrsp.circuit

    def stream_attach(self, stream, circuit):
        # print "stream", stream.id, "attached to circuit", circuit.id
        # print self.circuits[circuit.id].router.id_hex[1:]
        # print "with path:", '->'.join(map(lambda x: x.location.countrycode,
        #                                   circuit.path))
        pass

    def print_body(self, cdrsp, body):
        ip = None
        try:
            # j = json.loads(body)
            # ip = j["IP"]
            ip = body.replace("::ffff:", "").strip()
        except Exception as err:
            log.err(err)
        self.report(cdrsp.router, True, ip)

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
        # check.torproject.org/api/ip
        url = "http%s://ipinfo.io/ip" % ("s" if cdrsp.dest == 443 else "")
        d = agent.request("GET", url)
        d.addCallback(readBody)
        d.addCallback(functools.partial(self.print_body, cdrsp))

        canceler = e.reactor.callLater(15, d.cancel)
        d.addBoth(functools.partial(cancelCanceler, canceler))

        d.addErrback(functools.partial(self.failed, cdrsp.router,
                                       "socks5agent"))
        d.addErrback(log.err)

    def set_circuit(self, dest, router, circuit):
        cdrsp = CDRSP(circuit, dest, router)
        self.circuits[circuit.id] = cdrsp

    def circuit_built(self, circuit):
        c = self.circuits.get(circuit.id, None)
        if c is None:
            return  # ignore ... not our circuit
        d = txtorcon.util.available_tcp_port(self.exitaddr.reactor)
        d.addCallback(functools.partial(self.set_port, circuit))
        d.addErrback(functools.partial(self.failed, c.router,
                                       "available_tcp_port"))
        d.addErrback(log.err)

    def circuit_failed(self, circuit, **kw):
        c = self.circuits.get(circuit.id, None)
        if c is None:
            return  # ignore ... not our circuit
        # print 'Circuit %d failed "%s"' % (circuit.id, kw['REASON'])
        self.report(c.router, False)

    def failed(self, router, reason, failure):
        # trap these errors when confident
        if not failure.check(defer.CancelledError,
                             tserrors.ConnectionRefused,
                             tserrors.HostUnreachable,
                             ResponseNeverReceived):
            log.err(reason)
            log.err(failure.value)
        self.report(router, False)


def can_exit(descriptors, router, warn=False):
    dest = None
    desc = descriptors.get(router.id_hex[1:], None)

    if desc is None:
        if warn:
            print "No descriptor for", router.id_hex[1:]
        return (None, router)

    for port in [443, 80]:  # 6667
        if desc.exit_policy.can_exit_to(CHECK_IP, port):
            dest = port
            break

    if dest is None:
        if warn:
            print "Can't exit to", router.id_hex[1:]

    return (dest, router)


def in_consensus(state, router):
    e = state.routers_by_hash.get(norm(router), None)
    if e is None:
        print "Not in consensus", router
    return e


class Exitaddr(object):
    def __init__(self, reactor, options):
        self.reactor = reactor
        self.options = options

    def start(self):
        connection = TCP4ClientEndpoint(self.reactor, "localhost",
                                        self.options.control_port)
        d = txtorcon.build_tor_connection(connection)
        d.addCallback(self.setup_success)
        d.addErrback(self.setup_failed)
        try:
            self.reactor.run()
        except KeyboardInterrupt:
            pass

    def setup_failed(self, failure):
        self.reactor.stop()
        if failure.check(ConnectionRefusedError):
            print "Connection refused. Is tor running?"
        elif failure.check(CantExitException):
            print "No exits to test"
        else:
            print "Setup failed", failure

    def determine_exits(self, state):
        global can_exit

        if options.exits is not None:
            exits = map(lambda l: in_consensus(state, l), options.exits)
            exits = filter(lambda r: r is not None, exits)
        else:
            exits = state.routers_by_hash.values()
        exits = filter(lambda r: "exit" in r.flags, exits)

        # get descriptors from stem
        con = Controller.from_port(port = self.options.control_port)
        con.authenticate()
        descriptors = {}
        for desc in con.get_server_descriptors():
            descriptors[desc.fingerprint] = desc
        con.close()

        can_exit_func = functools.partial(can_exit, descriptors,
                                     warn=not options.num_exits)
        exits = map(can_exit_func, exits)
        exits = filter(lambda t: t[0] is not None, exits)

        if options.num_exits is not None:
            if options.num_exits > len(exits):
                print "Not enough exits. Giving you all I've got."
            else:
                exits = random.sample(exits, options.num_exits)

        return exits

    def setup_success(self, state):
        options = self.options
        exits = self.determine_exits(state)

        if len(exits) == 0:
            raise CantExitException

        if options.first_hop is None:
            # entry_guards will be empty with __DisablePredictedCircuits
            first_hop = random.choice(state.guards.values())
        else:
            first_hop = state.routers[norm(options.first_hop)]

        attacher = Attacher(state, exits, first_hop, self)
        attacher.start()

    def passed(self, result):
        raise NotImplementedError

    def failed(self, result):
        raise NotImplementedError

    def finished(self, results):
        raise NotImplementedError
