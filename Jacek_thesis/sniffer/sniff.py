import socket, sys
from struct import *
import re
from math import fabs

class transmission():
    def __init__(self):
        self.package_number=-1
        self.first_in_transmission=0
        self.ips=[]
        self.ip_list=''
        self.package=[]
        self.graph=''
    def analyse(self, packet):
        self.package_number+=1
        self.package.append(packet)
        graph=''
        cseq=re.search(r'^CSeq: ([0-9]*) (.*)', self.package[self.package_number]['data'], re.MULTILINE)
        source_ip=self.package[self.package_number]['source_ip']
        source_port=self.package[self.package_number]['source_port']
        destination_ip=self.package[self.package_number]['destination_ip']
        destination_port=self.package[self.package_number]['destination_port']

        if cseq:
            for ip in (source_ip,destination_ip):       #prepare list with all ips in transmission
                if ip not in self.ips:                  #and print these ips
                    self.ip_list=self.ip_list+ip.center(16, ' ')
                    graph='   '+self.ip_list+'\n'
                    self.ips.append(ip)
            request=str(cseq.group(1).strip() + ' ' + cseq.group(2).strip())
            source_ip_id=self.ips.index(source_ip)
            destination_ip_id=self.ips.index(destination_ip)
            if source_ip_id < destination_ip_id:
                delimeter_first = '|'
                delimeter_second = '>|'
            elif source_ip_id == destination_ip_id: #when destination and source ip are the same print confusing message
                delimeter_first = '?'
                delimeter_second = '?'
            else:
                delimeter_first = '|<'
                delimeter_second = '|'
            distance=int(fabs(int(destination_ip_id-source_ip_id)))
            graph+=str(self.package_number).center(3,' ')+8*' ' + delimeter_first + request.center(16*distance,'-') + delimeter_second
            message=str(self.package_number).center(8,'-')+'\n'+str(self.package[self.package_number]['data'])
            return {'graph':graph, 'message': message}
            #print graph
            
def sniff(transmission_protocol):
    global sip_transmission
    try:
        sip_transmission
    except NameError:
        sip_transmission=transmission()
    transmission_protocols={'UDP': socket.IPPROTO_UDP, 'TCP': socket.IPPROTO_TCP} #dictionary for transport protocol selection
    if transmission_protocol not in transmission_protocols.keys():
        sys.exit()
    try: #open a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, transmission_protocols[transmission_protocol])
    except socket.error, msg:
        print 'Socket could not be created. Error code: ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    packet = s.recvfrom(66746) #get a packet from socket
    packet = packet[0]
    ip_header_packed = packet[0:20] #first 20 characters = ip header

    try:
        ip_header = unpack('!BBHHHBBH4s4s', ip_header_packed) #unpack ip header
    except:
        print 'unpacking error'
        return None

    version_ihl = ip_header[0] #get ip version and header length
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ip_header_length = ihl * 4 

    ttl = ip_header[5] #time to leave
    protocol = ip_header[6] #transmission protocol, defined already, but why not [tcp=6; udp=17; icmp=1]
    source_address = socket.inet_ntoa(ip_header[8])
    destination_address = socket.inet_ntoa(ip_header[9])

    tcp_header_packed = packet[ip_header_length:ip_header_length+20] #get tcp header from whole packet
    try:
        tcp_header = unpack('!HHLLBBHHH', tcp_header_packed) #unpack it
    except:
        print 'unpacking error'
        return None
    
    source_port = tcp_header[0]
    destination_port = tcp_header[1]
    sequence = tcp_header[2]
    acknowledgement = tcp_header[3]
    thl = tcp_header[4] #temporary variable for getting tcp_header_lenght
    tcp_header_lenght = thl >> 4

    header_size = ip_header_length + tcp_header_lenght * 4 #get data from whole packet
    data_size = len(packet) - header_size
    data = packet[header_size:]

    protocol=re.search(r'^Via: (.*?)/', data, re.MULTILINE)
    if protocol:
        packet={
            'source_ip': str(source_address),
            'source_port': str(source_port),
            'destination_ip': str(destination_address),
            'destination_port': str(destination_port),
            'version': str(version),
            'ihl': str(ihl),
            'ttl': str(ttl),
            'protocol': str(protocol),
            'sequence': str(sequence),
            'acknowledgement': str(acknowledgement),
            'tcp_header_lenght': str(tcp_header_lenght),
            'data': str(data)
        }
        
        if protocol.group(1).strip() == 'SIP':
            #print sip_transmission.package[sip_transmission.package_number]['data']
            #sip_transmission.analyse(packet)
            return sip_transmission.analyse(packet)
        else:
            print 'protocol not reckognized' + str(protocol.group())

if __name__ == "__main__":
    while(1):
        sniff_results=sniff(sys.argv[1])
        if sniff_results:
            print sniff_results['graph']