from scapy.all import *

dest = sys.argv[1]
request = sys.argv[2]
ans=sr1(IP(dst=dest)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=request,qtype="A")))
ans.show()