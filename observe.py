from scapy.all import *

class entier:
    def __init__(self):
        self.val = 0
    def inc(self):
        self.val += 1
i = entier()

def maFonctionobs(a):
    i.inc()
    msg = str(i.val) + ': ' + a[IP].src + ' -> ' + a[IP].dst
    if (a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a'):
        if (a[DNS].qr==0L):
            msg = msg + ' <-- REQUEST for ' + a[DNS].qd[0].qname
            print msg
    if (a[DNS].qr==1L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')) and (a[DNS].ancount>0):
        if (a[DNS].ancount == 0):
            msg = msg + ' <--- ANSWER: empty '
        else:
            msg = msg + ' <-- ANSWER: ' + a[DNS].an[0].rdata
        print msg
        
def monFiltreobs(x):
    return (x.haslayer(DNS)) and (x.haslayer(UDP))
    

filtre = sys.argv[1]
sniff(count = 1000,lfilter = monFiltreobs,prn = maFonctionobs)
