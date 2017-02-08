#!/usr/bin/python3

import argparse
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q, A
from elasticsearch_dsl.query import Wildcard
import sys

### Constants ###

QUERY_SEARCH = 1
QUERY_VALUES = 2

### Helpers ###

def add_default_aggregation(s):
    a = A("terms", field="request.url.keyword", size=args.size)
    s.aggs.bucket("urls", a)

def add_domain_filter(s):
# add domain filters
    if args.domain:
        domain_filter = []
        for domain in args.domain:
            domain_filter.append(Wildcard(** { "host": domain }))
        return s.filter("bool", should=domain_filter)
    else:
        return s

def print_debug(*arglist):
    if args.debug:
        print(file=sys.stderr, *arglist)

### Query Subcommands ###

def query_missing(s, field, name, methods=None, responsecodes=None, invert=False):
    # main query
    q = Q("match", ** { field: name })
    if not invert:
        q = ~q
    s.query = q

    # add filters
    ## method
    if methods:
        s = s.filter("terms", ** { 'request.method': methods })
    ## response codes
    if responsecodes:
        for rc in responsecodes:
            rcrange = rc.split("-")
            if len(rcrange) == 2:
                s = s.filter("range", ** { 'response.status': { "gte": int(rcrange[0]), "lte": int(rcrange[1]) } })
            else:
                s = s.filter("term", ** { 'response.status': rc })

    print_debug(s.to_dict())
    return s

def query_missingheader(s, headername, methods=None, responsecodes=None, invert=False):
    s = query_missing(s, 'response.headernames', headername, methods, responsecodes, invert)
    return s

def query_missingparam(s, paramname, methods=None, responsecodes=None, invert=False):
    s = query_missing(s, 'request.parameternames', paramname, methods, responsecodes, invert)
    return s

def query_vals(s, field, name, values, invert):
    # match documents where given field value name is present, if required
    if values:
        q = Q("nested", path=field, query=Q("wildcard", ** { field + ".value.keyword": values }))
        if invert:
            s.query = ~q
        else:
            s.query = q
    else:
        s.query = Q()

    # 1. descent into response.headers/request.parameters
    # 2. filter given header
    # 3. aggregate values
    # 4. jump back into main document
    # 5. aggregate URLs
    s.aggs.bucket("field", "nested", path=field)\
            .bucket("valuefilter", "filter", Q("match", ** { field + ".name": name }))\
            .bucket("values", "terms", field=field + ".value.keyword", size=args.size)\
            .bucket("main", "reverse_nested")\
            .bucket("urls", "terms", field="request.url.keyword", size=args.size)
    return s

def query_responseheadervals(s, headername, values=None, invert=False):
    return query_vals(s, "response.headers", headername, values, invert)

def query_requestheadervals(s, headername, values=None, invert=False):
    return query_vals(s, "request.headers", headername, values, invert)

def query_parametervals(s, paramname, values=None, invert=False):
    return query_vals(s, "request.parameters", paramname, values, invert)

def query_cookievals(s, cookiename, values=None, invert=False):
    return query_vals(s, "response.cookies", cookiename, values, invert)

def query(s, q):
    s.query = Q("query_string", query=q)
    return s

### Main ###
argparser = argparse.ArgumentParser(description="WASE Query Tool")
argparser.add_argument("--server", "-s", default="localhost", help="ElasticSearch server")
argparser.add_argument("--index", "-i", default="wase-*", help="ElasticSearch index pattern to query")
argparser.add_argument("--size", "-S", default=10000, type=int, help="Maximum number of results of aggregation (default: %(default)s)")
argparser.add_argument("--field", "-f", action="append", help="Add fields to output. Prints full result instead of aggregated URLs.")
argparser.add_argument("--domain", "-d", action="append", help="Restrict search to domain. Wildcards allowed. Can be used multiple times.")
argparser.add_argument("--debug", "-D", action="store_true", help="Debugging output")
subargparsers = argparser.add_subparsers(title="Query Commands", dest="cmd")

argparser_missingheader = subargparsers.add_parser("missingheader", help="Search for URLs which responses are missing a header")
argparser_missingheader.add_argument("header", help="Name of the header")
argparser_missingheader.add_argument("--invert", "-i", action="store_true", help="Invert result, list all URLs where header is set")
argparser_missingheader.add_argument("--method", "-m", action="append", help="Restrict search to given methods")
argparser_missingheader.add_argument("--responsecode", "-c", action="append", help="Restrict search to responses with the given codes. Can be a single code (e.g. 200), a range (200-299) or wildcard (2*)")

argparser_missingparam = subargparsers.add_parser("missingparameter", help="Search for URLs where the requests are missing a parameter with the given name")
argparser_missingparam.add_argument("parameter", help="Name of parameter to search")
argparser_missingparam.add_argument("--invert", "-i", action="store_true", help="Invert result, list all URLs where header is set")
argparser_missingparam.add_argument("--method", "-m", action="append", help="Restrict search to given methods")
argparser_missingparam.add_argument("--responsecode", "-c", action="append", help="Restrict search to responses with the given codes. Can be a single code (e.g. 200), a range (200-299) or wildcard (2*)")
#argparser_missingparam.add_argument("--type", "-t", choices=["url", "body", "cookie", "xml", "xmlattr", "multipartattr", "json", "unknown"], help="Restrict search to given request parameter type")

argparser_responseheadervals = subargparsers.add_parser("responseheadervalues", help="Show all response header values and the URLs where the value was set")
argparser_responseheadervals.add_argument("--urls", "-u", action="store_true", help="List URLs where header value is set")
argparser_responseheadervals.add_argument("--max-urls", "-n", type=int, default=0, help="Maximum number of listed URLs")
argparser_responseheadervals.add_argument("--values", "-v", help="Restrict to values matching the given pattern (wildcards allowed)")
argparser_responseheadervals.add_argument("--invert", "-i", action="store_true", help="Invert values search")
argparser_responseheadervals.add_argument("header", help="Name of the response header")

argparser_requestheadervals = subargparsers.add_parser("requestheadervalues", help="Show all request header values and the URLs where the value was set")
argparser_requestheadervals.add_argument("--urls", "-u", action="store_true", help="List URLs where header value is set")
argparser_requestheadervals.add_argument("--max-urls", "-n", type=int, default=0, help="Maximum number of listed URLs")
argparser_requestheadervals.add_argument("--values", "-v", help="Restrict to values matching the given pattern (wildcards allowed)")
argparser_requestheadervals.add_argument("--invert", "-i", action="store_true", help="Invert values search")
argparser_requestheadervals.add_argument("header", help="Name of the response header")

argparser_cookievals = subargparsers.add_parser("cookievalues", help="Show all cookie values and the URLs where the value was set")
argparser_cookievals.add_argument("--urls", "-u", action="store_true", help="List URLs where header value is set")
argparser_cookievals.add_argument("--max-urls", "-n", type=int, default=0, help="Maximum number of listed URLs")
argparser_cookievals.add_argument("--values", "-v", help="Restrict to values matching the given pattern (wildcards allowed)")
argparser_cookievals.add_argument("--invert", "-i", action="store_true", help="Invert values search")
argparser_cookievals.add_argument("cookie", help="Name of the cookie")

argparser_paramvals = subargparsers.add_parser("parametervalues", help="Show all request parameter values and the URLs where the value was set")
argparser_paramvals.add_argument("--urls", "-u", action="store_true", help="List URLs where parameter value is set")
argparser_paramvals.add_argument("--max-urls", "-n", type=int, default=0, help="Maximum number of listed URLs")
argparser_paramvals.add_argument("--values", "-v", help="Restrict to values matching the given pattern (wildcards allowed)")
argparser_paramvals.add_argument("--invert", "-i", action="store_true", help="Invert values search")
argparser_paramvals.add_argument("parameter", help="Name of the request parameter")

argparser_search = subargparsers.add_parser("search", help="Make arbitrary queries")
argparser_search.add_argument("query", nargs="*", default=["*"], help="Query string")

args = argparser.parse_args()
print_debug(args)

es = Elasticsearch(args.server)
s = Search(using=es).index(args.index)
r = None

querytype = None
if args.cmd == "missingheader":
    s = query_missingheader(s, args.header, args.method, args.responsecode, args.invert)
    querytype = QUERY_SEARCH
elif args.cmd == "missingparameter":
    s = query_missingparam(s, args.parameter, args.method, args.responsecode, args.invert)
    querytype = QUERY_SEARCH
elif args.cmd == "responseheadervalues":
    s = query_responseheadervals(s, args.header, args.values, args.invert)
    querytype = QUERY_VALUES
elif args.cmd == "requestheadervalues":
    s = query_requestheadervals(s, args.header, args.values, args.invert)
    querytype = QUERY_VALUES
elif args.cmd == "cookievalues":
    s = query_cookievals(s, args.cookie, args.values, args.invert)
    querytype = QUERY_VALUES
elif args.cmd == "parametervalues":
    s = query_parametervals(s, args.parameter, args.values, args.invert)
    querytype = QUERY_VALUES
elif args.cmd == "search":
    s = query(s, " ".join(args.query))
    querytype = QUERY_SEARCH
else:
    argparser.print_help()
    sys.exit(1)

s = add_domain_filter(s)

if querytype == QUERY_SEARCH:
    if args.field:
        print_debug(s.to_dict())
        r = s.scan()
    else:
        add_default_aggregation(s)
        print_debug(s.to_dict())
        r = s.execute()

    if not r:
        print("No matches!")
        sys.exit(0)
    if args.field:
        for d in r:
            print(d['request']['url'])
            for f in args.field:
                print(f, end=": ")
                fl = f.split(".", 1)
                try:
                    if len(fl) == 2:
                        print(d[fl[0]][fl[1]])
                    else:
                        print(d[f])
                except KeyError:
                    print("-")
            print()
    else:
        for d in r.aggregations.urls.buckets:
            print(d['key'])
elif querytype == QUERY_VALUES:
    print_debug(s.to_dict())
    r = s.execute()

    for hv in r.aggregations.field.valuefilter.values.buckets:
        print(hv.key)
        if args.urls:
            urlcnt = -1
            if args.max_urls > 0:
                urlcnt = args.max_urls

            for url in hv.main.urls.buckets:
                print(url.key)
                if urlcnt >= 0:
                    urlcnt -= 1
                if urlcnt == 0:
                    break
            print()
