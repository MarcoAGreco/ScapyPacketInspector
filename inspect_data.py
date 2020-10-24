from scapy.all import *
from geoip import geolite2 
import sys
import matplotlib.pyplot as plt
import numpy as np
import socket
from scapy.layers.http import HTTPRequest, HTTPResponse

class Analitycs:
    def __init__(self, n_tcp, n_udp, n_icmp, n_other):
        self.n_tcp = n_tcp
        self.n_udp = n_udp
        self.n_icmp = n_icmp
        self.n_other = n_other

class TCP_data:
    def __init__(self, src, dst, MAC_src, MAC_dst, chksum, ip_proto, tcp_flags, loc_dst, loc_src, sport, dport):
            self.src = src
            self.dst = dst
            self.MAC_src = MAC_src
            self.MAC_dst = MAC_dst  
            self.chksum = chksum
            self.ip_proto = ip_proto
            self.tcp_flags = tcp_flags
            self.loc_dst = loc_dst
            self.loc_src = loc_src
            self.sport = sport
            self.dport = dport

    def print():
        print('Src:', self.src)
        print('Dst:', self.dst)
        print('MAC-src:', self.MAC_src)
        print('MAC-dst:', self.MAC_dst)
        print('Checksum:', self.chksum)
        print('IP protocol:', self.ip_proto)
        print('TCP flags:', self.tcp_flags)
        print('Dst Location:', self.loc_dst)
        print('Src Location:', self.loc_src)
        print('Dst port:', self.dport)
        print('Src port:', self.sport)
        

def show_results(analitycs):
    proto = ('TCP ', 'UDP', 'ICMP', 'Other')
    y_pos = np.arange(len(proto))
    values = [analitycs.n_tcp, analitycs.n_udp, analitycs.n_icmp, analitycs.n_other]

    plt.bar(y_pos, values, align='center', alpha=0.5)
    plt.xticks(y_pos, proto)
    plt.title('Packet classifiation.')

    plt.show()
    

def analyze(pkts):
    analitycs = Analitycs(0, 0, 0, 0)
    
    # pkts[0].pdfdump(layer_shift=1) # sudo apt install texlive-latex-base  
    # pkts[20].pdfdump(layer_shift=1) 
    # pkts[250].pdfdump(layer_shift=1) 
    
    for pkt in pkts:
        if TCP in pkt:
            analitycs.n_tcp += 1

            src = pkt[IP].src
            dst = pkt[IP].dst
            MAC_src = pkt.src
            MAC_dst = pkt.dst
            chksum = pkt[IP].chksum
            ip_proto = pkt[IP].proto

            tcp_flags = pkt[TCP].flags
            tcp_sport = pkt[TCP].sport
            tcp_dport = pkt[TCP].dport
            payload_guess = pkt[TCP].payload_guess

            #loc_dst = geolite2.lookup(src)
            #loc_src = geolite2.lookup(dst)
            #raw = pkt.raw()

            #tcp_data = TCP_data(src, dst, MAC_src, MAC_dst, chksum, ip_proto, tcp_flags, loc_dst, loc_src)
            #tcp_data.print()

        elif UDP in pkt:
            analitycs.n_udp += 1

            src = pkt[IP].src
            dst = pkt[IP].dst
            MAC_src = pkt.src
            MAC_dst = pkt.dst
            chksum = pkt[IP].chksum
            ip_proto = pkt[IP].proto

            udp_len = pkt[UDP].len
            udp_chksum = pkt[UDP].len
            udp_sport = pkt[UDP].sport
            udp_dport = pkt[UDP].dport
            payload_guess = pkt[UDP].payload_guess
            # print('UDP guess', payload_guess)

        elif ICMP in pkt:
            analitycs.n_icmp += 1

            src = pkt[IP].src
            dst = pkt[IP].dst
            MAC_src = pkt.src
            MAC_dst = pkt.dst
            chksum = pkt[IP].chksum
            ip_proto = pkt[IP].proto

            icmp_type = pkt[ICMP].type
            icmp_code = pkt[ICMP].code
            icmp_chksum = pkt[ICMP].chksum
            icmp_id = pkt[ICMP].id
            icmp_seq = pkt[ICMP].seq
            icmp_length = pkt[ICMP].length
            icmp_nexthopmtu = pkt[ICMP].nexthopmtu
            class_guess = pkt[ICMP].guess_payload_class
        else:
            analitycs.n_other += 1

    show_results(analitycs)

def analyze_sessions(session):
    for pkt in session:
        if pkt.haslayer(HTTPRequest):
            host = pkt[HTTPRequest].Host.decode()
            path = pkt[HTTPRequest].Path.decode()

            url = host + path
            src = pkt[IP].src
            MAC_src = pkt.src
            method = pkt[HTTPRequest].Method.decode()

            if pkt.haslayer(Raw):
                raw = pkt[Raw].load
                # print(''+method+' '+url+'\n'+raw)
            else:
                null = 0
                # print(''+method+' '+url)

        if pkt.haslayer(HTTPResponse):
            dst = pkt[IP].dst
            src = pkt[IP].src

            version = pkt[HTTPResponse].Http_Version.decode()
            s_code = pkt[HTTPResponse].Status_Code.decode()
            s_code_s =pkt[HTTPResponse].Reason_Phrase.decode()
            cont_encod = pkt[HTTPResponse].Content_Encoding
            cont_len = pkt[HTTPResponse].Content_Length.decode()
            cont_type = pkt[HTTPResponse].Content_Type


            if pkt.haslayer(Raw):
                raw = pkt[Raw].load
                # print(src+' response '+s_code+' '+s_code_s+' to'+dst+'\n'+str(raw))
            else:
                null = 0
                # print(src+' response '+s_code+' '+s_code_s+' to'+dst)

def sniff_offline(pcap):
    # sniff(offline=pcap, prn=analyze)
    pkts = rdpcap(pcap)
    analyze(pkts)
    
    sniff(offline=pcap, session=TCPSession, prn=analyze_sessions) 

def main():
    print("[INFO] Start analyzing packer: ", sys.argv[1])
    sniff_offline(sys.argv[1])

if __name__ == "__main__":
    main()