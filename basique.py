from scapy.all import *

def maFonction(a):
    msg = str(i) + ': ' + a[IP].src + ' -> ' + a[IP].dst
    if (a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a'):
    	msg = msg + ' <------------------------'
    print msg

filtre = sys.argv[1]
i = 0
a = sniff(count = 1000,lfilter = lambda x: x.haslayer(IP),prn = maFonction)
#i = i+1
