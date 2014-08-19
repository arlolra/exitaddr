#!/usr/bin/env python

import json

from twisted.web import server, resource
from twisted.internet import reactor

from common import Exitaddr, options

DEFAULT_PORT = 8080

exitaddr_results = None


def addHeader(request):
    h = request.responseHeaders
    h.addRawHeader(b"content-type", b"application/json")


class Res(resource.Resource):
    def getChild(self, name, request):
        ''' handle trailing / '''
        if name == '':
            return self
        return resource.Resource.getChild(self, name, request)


class Exits(Res):
    ''' json dump of our state '''
    def render_GET(self, request):
        addHeader(request)
        return json.dumps(exitaddr_results)


class IP(Res):
    ''' json response with the remote host ip '''
    def render_GET(self, request):
        host = request.transport.getPeer().host
        header = request.received_headers.get("X-Forwared-For", None)
        if header is not None:
            host = header.split(',')[-1].strip()
        response = {"IP": host}
        addHeader(request)
        return json.dumps(response)


class Ser(Exitaddr):
    def __init__(self, *args, **kwargs):
        Exitaddr.__init__(self, *args, **kwargs)

    def passed(self, result):
        pass

    def failed(self, result):
        pass

    def finished(self, results):
        global exitaddr_results
        res = {}
        for key in results.keys():
            res[key] = results[key][1]
        exitaddr_results = res
        print "exit list ready!"


def main():
    root = resource.Resource()
    root.putChild("exits", Exits())
    root.putChild("ip", IP())
    reactor.listenTCP(DEFAULT_PORT, server.Site(root))

    # sample a few for now
    options.num_exits = 25

    exitaddr = Ser(reactor, options)
    print "listening on", DEFAULT_PORT
    exitaddr.start()


if __name__ == "__main__":
    main()
