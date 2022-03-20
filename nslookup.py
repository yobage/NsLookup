import sys

i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *

sys.stdin, sys.stdout, sys.stderr = i, o, e


def print_domain(packet):
    print(packet[DNSQR].qname.decode())


def filter_dns_typea(packet):
    if (DNS in packet) and (DNSQR in packet):
        return (packet[DNS].opcode == 0 and packet[DNSQR].qtype == 1)


def main():
    print(sys.argv)
    if (len(sys.argv) > 1):
        if (len(sys.argv) == 2):

            query_val = sys.argv[1]
            query_val=query_val.splice(1)
            print(query_val)
            dns_packet = IP(dst='8.8.8.8') / UDP(sport=55555, dport=53) / DNS(qdcount=1) / DNSQR(qname=query_val)
            response = sr1(dns_packet, verbose=0)
            for i in range(response[DNS].ancount):
                print(type(response[DNS].an[i].rdata))
                if (type(response[DNS].an[i].rdata)) == str:
                    print(response[DNS].an[i].rdata)
            for i in range(response[DNS].ancount):
                if response[DNS][i] and response[DNS].an[i].type == 5:
                    print(response[DNS].an[i].rdata.decode())
        else:
            query_type = (sys.argv[1]).upper()
            query_val = sys.argv[2]
            if (query_type == "-TYPE=A"):
                dns_packet = IP(dst='8.8.8.8') / UDP(sport=55555, dport=53) / DNS(qdcount=1) / DNSQR(qname=query_val)
                response = sr1(dns_packet, verbose=0)
                for i in range(response[DNS].ancount):
                    if (type(response[DNS].an[i].rdata)) == str:
                        print(response[DNS].an[i].rdata)
                for i in range(response[DNS].ancount):
                    if response[DNS][i] and response[DNS].an[i].type == 5:
                        print(response[DNS].an[i].rdata.decode())

            elif (query_type == "-TYPE=PTR"):
                ip = query_val
                
                ip = ip.split('.')
                ip.reverse()
                ip = '.'.join(ip) + ".in-addr.arpa"
                answer = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=ip, qtype='PTR')), verbose=0)
                print(answer["DNS"].an.rdata[:-1].decode())
            else:
                print("try again")
    else:
        print("please add parameter")


if __name__ == "__main__":
    # Call the main handler function
    main()
