#!/usr/bin/env python

import json

from twisted.web import server, resource
from twisted.internet import reactor

from common import Exitaddr, options

DEFAULT_PORT = 8080


def addHeader(request):
    request.responseHeaders.addRawHeader(b"content-type",
                                         b"application/json")


class Res(resource.Resource):
    def getChild(self, name, request):
        ''' handle trailing / '''
        if name == '':
            return self
        return resource.Resource.getChild(self, name, request)


class Exits(Res):
    ''' json dump of our state '''
    def render_GET(self, request):
        response = {}
        addHeader(request)
        return json.dumps(response)


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
        pass


def main():
    root = resource.Resource()
    root.putChild("exits", Exits())
    root.putChild("ip", IP())
    reactor.listenTCP(DEFAULT_PORT, server.Site(root))
    exitaddr = Ser(reactor, options)
    exitaddr.start()


if __name__ == "__main__":
    main()
