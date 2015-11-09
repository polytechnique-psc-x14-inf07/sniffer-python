from scapy.all import *


filtre = sys.argv[1]
i = 0
while 1:
	a = sniff(count = 1,lfilter = lambda x: x.haslayer(IP))[0]
	i = i+1
	msg = str(i) + ': ' + a[IP].src + ' -> ' + a[IP].dst
	if (a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a'):
		msg = msg + ' <------------------------'
	print msg