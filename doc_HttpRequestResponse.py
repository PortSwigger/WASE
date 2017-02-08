# WASE - Web Audit Search Engine
# doc_HttpRequestResponse.py: Implementation of the core data structure
# 
# Copyright 2016 Thomas Patzke <thomas@patzke.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from elasticsearch_dsl import DocType, Text, Keyword, Integer, Short, Date, Object, Nested, MetaField, analyzer
from datetime import datetime
import re
from WASEHTMLParser import WASEHTMLParser
from tzlocal import get_localzone

reHeader = re.compile("^(.*?):\s*(.*)$")
tz = get_localzone()

def parse_header(header):
    # TODO: support for multiline headers
    match = reHeader.search(header)
    if match:
        return { 'name': match.group(1), 'value': match.group(2) }
    else:
        raise ValueError("No header matched")

identifierAnalyzer = analyzer("identifier",
        tokenizer = "keyword",
        filter = ["lowercase"]
        )

class DocHTTPRequestResponse(DocType):
    class Meta:
        doc_type = 'HTTPRequestResponse'

    timestamp = Date()
    protocol = Keyword()
    host = Keyword()
    port = Integer()
    request = Object(
            properties = {
                'method': Keyword(),
                'url': Text(fields={'keyword': Keyword()}),
                'requestline': Text(fields={'keyword': Keyword()}),
                'content_type': Text(fields={'keyword': Keyword()}),
                'headernames': Text(analyzer=identifierAnalyzer, multi=True, fields={'keyword': Keyword()}),
                'headers': Nested(
                    properties = {
                        'name': Text(analyzer=identifierAnalyzer, fields={'keyword': Keyword()}),
                        'value': Text(fields={'keyword': Keyword()})
                        }
                    ),
                'parameternames': Text(analyzer=identifierAnalyzer, multi=True, fields={'keyword': Keyword()}),
                'parameters': Nested(
                    properties = {
                        'type': Keyword(),
                        'name': Text(analyzer=identifierAnalyzer, fields={'keyword': Keyword()}),
                        'value': Text(fields={'keyword': Keyword()})
                        }
                    ),
                'body': Text(include_in_all=False)
                }
            )
    response = Object(
            properties = {
                'status': Short(),
                'responseline': Text(fields={'keyword': Keyword()}),
                'content_type': Text(fields={'keyword': Keyword()}),
                'inferred_content_type': Text(fields={'keyword': Keyword()}),
                'headernames': Text(analyzer=identifierAnalyzer, multi=True, fields={'keyword': Keyword()}),
                'headers': Nested(
                    properties = {
                        'name': Text(analyzer=identifierAnalyzer, fields={'keyword': Keyword()}),
                        'value': Text(fields={'keyword': Keyword()})
                        }
                    ),
                'cookienames': Text(analyzer=identifierAnalyzer, multi=True, fields={'keyword': Keyword()}),
                'cookies': Nested(
                    properties = {
                        'domain': Text(fields={'keyword': Keyword()}),
                        'expiration': Date(fields={'keyword': Keyword()}),
                        'name': Text(analyzer=identifierAnalyzer, fields={'keyword': Keyword()}),
                        'path': Text(fields={'keyword': Keyword()}),
                        'value': Text(fields={'keyword': Keyword()})
                        }
                    ),
                'body': Text(include_in_all=False),
                'doctype': Text(multi=True, fields={'keyword': Keyword()}),
                'base': Text(multi=True, fields={'keyword': Keyword()}),
                'stylesheets': Text(multi=True, fields={'keyword': Keyword()}),
                'frames': Text(multi=True, fields={'keyword': Keyword()}),
                'scripts': Text(multi=True, fields={'keyword': Keyword()}),
                'links': Text(multi=True, fields={'keyword': Keyword()}),
                'images': Text(multi=True, fields={'keyword': Keyword()}),
                'audio': Text(multi=True, fields={'keyword': Keyword()}),
                'video': Text(multi=True, fields={'keyword': Keyword()}),
                'objects': Text(multi=True, fields={'keyword': Keyword()}),
                'formactions': Text(multi=True, fields={'keyword': Keyword()}),
                'extrefs': Text(multi=True, fields={'keyword': Keyword()}),    # all external references
                }
            )

    def add_request_header(self, header):
        parsed = parse_header(header)
        self.request.headers.append(parsed)
        self.request.headernames.append(parsed['name'])

    def add_response_header(self, header):
        parsed = parse_header(header)
        self.response.headers.append(parsed)
        self.response.headernames.append(parsed['name'])

    def add_parsed_request_header(self, name, value):
        self.request.headers.append({"name": name, "value": value})
        self.request.headernames.append(name)

    def add_parsed_response_header(self, name, value):
        self.response.headers.append({"name": name, "value": value})
        self.response.headernames.append(name)

    def add_request_parameter(self, typename, name, value):
        param = { 'type': typename, 'name': name, 'value': value }
        self.request.parameters.append(param)
        self.request.parameternames.append(param['name'])

    def add_response_cookie(self, name, value, domain=None, path=None, expiration=None):
        cookie = { 'name': name, 'value': value, 'domain': domain, 'path': path, 'expiration': expiration }
        self.response.cookies.append(cookie)
        self.response.cookienames.append(cookie['name'])

    def save(self, storeResponseBody=True, **kwargs):
        if not self.timestamp:
            self.timestamp = datetime.now(tz)                 # TODO: timestamp options: now (as is), request and response
        if self.response.body and ((self.response.inferred_content_type and self.response.inferred_content_type == "HTML") or (not self.response.inferred_content_type and "HTML" in self.response.content_type or "html" in self.response.content_type)):
            parser = WASEHTMLParser()
            parser.feed(self.response.body)
            parser.close()

            self.response.doctype = list(parser.doctype)
            self.response.base = list(parser.base)
            self.response.stylesheets = list(parser.stylesheets)
            self.response.frames = list(parser.frames)
            self.response.scripts = list(parser.scripts)
            self.response.links = list(parser.links)
            self.response.images = list(parser.images)
            self.response.audio = list(parser.audio)
            self.response.video = list(parser.video)
            self.response.objects = list(parser.objects)
            self.response.formactions = list(parser.formactions)
            self.response.extrefs = list(parser.extrefs)

        if not storeResponseBody:
            self.response.body = None
        return super(DocHTTPRequestResponse, self).save(**kwargs)
