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
    if (a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a'):
        if (a[DNS].qr==0L):
            msg = msg + ' <-- REQUEST for ' + a[DNS].qd[0].qname
        else:
            msg = msg + ' <-- RESPONSE'
        print msg

filtre = sys.argv[1]
a = sniff(count = 1000,lfilter = lambda x: x.haslayer(DNS),prn = maFonction)