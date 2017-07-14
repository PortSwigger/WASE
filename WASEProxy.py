#!/usr/bin/env python
# Intercepting Proxy that feeds HTTP(S) requests/responses into ElasticSearch based on pymiproxy and WASE

from miproxy.proxy import ProxyHandler, MitmProxy, AsyncMitmProxy
import argparse
from httplib import HTTPResponse
from Cookie import SimpleCookie
from doc_HttpRequestResponse import DocHTTPRequestResponse
from StringIO import StringIO
from SocketServer import ForkingMixIn
from BaseHTTPServer import BaseHTTPRequestHandler
import re
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Index

args = None
storeResponseBody = True
reContentType = re.compile("^(.*?)(?:$|\s*;)")

class ForkingAsyncMitmProxy(ForkingMixIn, MitmProxy):
    pass

class WASEProxyHandler(ProxyHandler):
    """Intercepts HTTP(S) requests/responses, extracts data and feeds ElasticSearch"""
    def mitm_request(self, data):
	# Initialize ES connection and index
	res = connections.create_connection(hosts=[args.elasticsearch])
	idx = Index(args.index)
	idx.doc_type(DocHTTPRequestResponse)
	try:
	    DocHTTPRequestResponse.init()
	    idx.create()
	except:
	    pass

        r = HTTPRequest(data)

        # determine url
        if self.is_connect:
            scheme = "https"
        else:
            scheme = "http"
        url = scheme + "://" + self.hostname
        if scheme == "http" and int(self.port) != 80 or scheme == "https" and int(self.port) != 443:
            url += ":" + str(self.port)
        url += self.path

        if args.verbose:
            print(url)

        self.doc = DocHTTPRequestResponse(host=self.hostname, port=int(self.port), protocol=scheme)
        self.doc.meta.index = args.index
        self.doc.request.url = url
        self.doc.request.requestline = r.requestline
        self.doc.request.method = r.command
        self.doc.host = self.hostname
        self.doc.port = int(self.port)
        self.doc.protocol = scheme
            
        return data

    def mitm_response(self, data):
        lines = data.split("\r\n")
        r = HTTPResponse(FakeSocket(data))
        r.begin()

        # response line
        self.doc.response.status = r.status
        self.doc.response.responseline = lines[0].decode(args.charset, args.encodingerrors)

        # headers
        ct = ""
        cookies = list()
        for header in r.getheaders():
            name = header[0].decode(args.charset, args.encodingerrors)
            value = header[1].decode(args.charset, args.encodingerrors)
            self.doc.add_parsed_response_header(name, value)
            if name == "content-type":
                ct = value
            elif name == "set-cookie":
                cookies.append(value)

        # content type
        try:
            m = reContentType.search(ct)
            self.doc.response.content_type = m.group(1)
        except:
            pass

        # cookies
        for cookie in cookies:
            # TODO: the following code extracts only partial cookie data - check/rewrite
            try:
                pc = SimpleCookie(cookie)
                for name in pc.keys():
                    c = pc[name]
                    try:
                        value = c.value
                    except AttributeError:
                        value = None
                    try:
                        domain = c.domain
                    except AttributeError:
                        domain = None
                    try:
                        path = c.path
                    except AttributeError:
                        path = None
                    try:
                        exp = c.expires
                    except AttributeError:
                        exp = None
                    self.doc.add_response_cookie(name, value, domain, path, exp)
            except:
                pass

        # body
        bodybytes = r.read()
        self.doc.response.body = bodybytes.decode(args.charset, args.encodingerrors)

        self.doc.save(storeResponseBody)
        return data

# code copied from http://stackoverflow.com/questions/24728088/python-parse-http-response-string
class FakeSocket():
    def __init__(self, response_str):
        self._file = StringIO(response_str)

    def makefile(self, *args, **kwargs):
        return self._file

# code copied from http://stackoverflow.com/questions/2115410/does-python-have-a-module-for-parsing-http-requests-and-responses
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

### Main ###
argparser = argparse.ArgumentParser(description="Intercepting HTTP(S) proxy that forwards data into ElasticSearch WASE datastructure")
argparser.add_argument("--listenaddr", "-l", default="localhost", help="IP/hostname the server binds to (default: %(default)s)")
argparser.add_argument("--port", "-p", type=int, default=8080, help="Port the proxy server listens to (default: %(default)s)")
argparser.add_argument("--elasticsearch", "-e", default="localhost", help="ElasticSearch instance (default: %(default)s)")
argparser.add_argument("--index", "-i", default="wase-proxy", help="ElasticSearch index (default: %(default)s)")
argparser.add_argument("--no-response-body", "-n", action="store_true", help="Don't store response body in ElasticSearch")
argparser.add_argument("--charset", "-c", default="utf-8", help="Character set used for decoding of bytes responses into string passed to ES (default: %(default)s)")
argparser.add_argument("--encodingerrors", "-E", default="ignore", choices=["ignore", "replace", "strict"], help="Behavior when encoding errors occur, must be ignore, replace or strict (default: %(default)s)")
argparser.add_argument("--verbose", "-v", action="store_true", help="Be verbose")
args = argparser.parse_args()

if args.no_response_body:
    storeResponseBody = False

# run proxy
proxy = ForkingAsyncMitmProxy(RequestHandlerClass=WASEProxyHandler, server_address=(args.listenaddr, args.port))
try:
    proxy.serve_forever()
except KeyboardInterrupt:
    proxy.server_close()
