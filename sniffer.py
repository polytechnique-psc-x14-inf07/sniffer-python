#-*-coding:Utf-8-*-
#---------------------------------------------
#	   iPsilon Trame Sniffer
# by iZy_TeH_PariaH
# version 1.0
# python 2.6, Ubuntu
#---------------------------------------------
# For CyberPeace and Harmony ;-)
#---------------------------------------------
from scapy.all import *

class snifferBot:
	def __init__(self,filtre,host):
		self.TCP = 0
		self.UDP = 0
		self.ICMP = 0
		self.ARP = 0
		self.host = host
		self.setProto(filtre)
		self.run()
	def setProto(self,filtre):  #Argument demandant le protocole
		if filtre != '-a':
			self.TCP = 0
			self.UDP = 0
			self.ICMP = 0
			self.ARP = 0
			if 'tcp' in filtre:
				self.TCP = 1
			if 'udp' in filtre:
				self.UDP = 1
			if 'icmp' in filtre:
				self.ICMP = 1
			if 'arp' in filtre:
				self.ARP = 1
		else:
			self.TCP = 1
			self.UDP = 1
			self.ICMP = 1
			self.ARP = 1
		
	def run(self):
		while 1:
			infos = []
			a = sniff(count = 1)[0]
			isIP = self.returnIP(a)
		#---------------------------------------------
			#Récupération ipSource / ipDst
		#---------------------------------------------
			if isIP != 99:
				infos.append(a[IP].src)
				infos.append(a[IP].dst)
			else:
				infos.append(0)
				infos.append(0)
			if infos[0] == self.host or infos[1] == self.host or self.host == '-a':
		#---------------------------------------------
			#Récupération Raw
		#---------------------------------------------
				raw = self.returnRaw(a)
				#si c'est TCP
				if self.isTCP(a) != 99 and self.TCP == 1:
					msg = '[\033[31mTCP\033[00m]\033[34m '
					msg += infos[0] + '\033[00m:\033[35m' + str(a[TCP].sport) + '\033[00m -> \033[34m' + infos[1] + '\033[00m:\033[35m' + str(a[TCP].dport) + '\033[00m/ \033[31mflags\033[00m : \033[35m' + str(a[TCP].flags) + '\033[00m / \033[31mseq\033[00m = \033[35m' + str(a[TCP].seq) + '\033[00m\033[31m ack \033[00m= \033[35m' + str(a[TCP].ack) + '\033[00m'
					if raw != 99:
						msg += '/\033[31m Raw \033[00m:\033[01m ' + raw.load + '\033[00m'
						print msg
			#si c'est UDP
				elif self.isUDP(a) != 99 and self.UDP == 1:
					msg = '[\033[31mUDP\033[00m]\033[34m '
					msg += infos[0] + '\033[00m:\033[35m' + str(a[UDP].sport) + '\033[00m -> \033[34m' + infos[1] + '\033[00m:\033[35m' + str(a[UDP].dport)
					if raw != 99:
						msg += '/\033[31m Raw \033[00m:\033[01m ' + raw.load + '\033[00m'
						print msg
			#Si c'est ICMP
				elif self.isICMP(a) != 99 and self.ICMP == 1:
					msg = '[\033[31mICMP\033[00m]\033[32m '
					msg += infos[0] + ' -> ' + infos[1] + '/'
					msg += 'type = ' + self.getICMPType(a) + '\033[00m'
					print msg
			#Si c'est ARP
				elif self.isARP(a) != 99 and self.ARP == 1:
					msg = '[\033[31mARP\033[00m] '
					msg += '\033[34m' + a[ARP].psrc + '\033[00m (\033[35m' + a[Ether].src + '\033[00m) -> \033[34m' + a[ARP].pdst + '\033[00m (\033[35m' + a[Ether].dst + '\033[00m) / Op = \033[01m' + self.getARPop(a) + '\033[00m'
					print msg
	
	def isTCP(self,paquet):
		try:
			return paquet[TCP]
		except:
			return 99
	def isUDP(self,paquet):
		try:
			return paquet[UDP]
		except:
			return 99
	def isARP(self,paquet):
		try:
			return paquet[ARP]
		except:	
			return 99
	def isICMP(self,paquet):
		try:
			return paquet[ICMP]
		except:
			return 99
	
	def returnRaw(self,paquet):
		try:
			return paquet[Raw]
		except:
			return 99
	
	def returnIP(self,paquet):
		try:
			return paquet[IP]
		except:
			return 99
	def getARPop(self,paquet):
		t = paquet[ARP].op
		if t == 1:
			return 'Request (Who-has)'
		elif t == 2:
			return 'Reply'
	def getICMPType(self,paquet):
		t = paquet[ICMP].type
		u = paquet[ICMP].code
		if t == 0:
			return 'echo-reply'
		elif t == 3:
			if u == 0:
				return 'Reseau Inaccessible'
			elif u == 1:
				return 'Machine inaccessible'
			elif u == 2:
				return 'Protocole inaccessible'
			elif u == 3:
				return 'Port inacessible'
			elif u == 4:
				return 'Fragmentation necessaire mais impossible'
			elif u == 5:
				return 'Echec du routage'
			elif u == 6:
				return 'Reseau inconnu'
			elif u == 7:
				return 'Machine inconnue'
			elif u == 8:
				return 'Machine non connectée au reseau'
			elif u == 9:
				return 'Comunication avec le reseau interdite'
			elif u == 10:
				return 'Communcation avec la machine interdite'
			elif u == 11:
				return 'Reseau inaccessible pour ce service'
			elif u == 12:
				return 'Machine inacessible pour ce service'
			elif u == 13:
				return 'Communication interdite [Filtre]'
			elif u == 14:
				return 'Priorité d\'hôte violé'
			elif u == 15:
				return 'Limite de priorité atteinte'
		elif t == 4:
			return 'Extinction de la source'
		elif t == 5:
			return 'Redirection'
		elif t == 8:
			return 'Echo-request'
		elif t == 11:
			return 'Timeout'
		elif t == 12:
			return 'Entête erronée'
		elif t == 13:
			return 'Demande d\'heure'
		elif t ==  14:
			return 'Reponse heure'
		elif t == 15:
			return 'Demande IP'
		elif t == 16:
			return 'Reponse IP'
		elif t == 17:
			return 'Demande masque de sous réseau'
		elif t == 18:
			return 'Reponse masque de sous réseau'
if __name__ == '__main__':
	if len(sys.argv) < 3:
		print 'Syntaxe : !/.py -filtre -host'
		print '-a = all'
		print 'filtres : tcp udp icmp arp'
		exit(0)
	filtre = sys.argv[1]
	host = sys.argv[2]
	a = snifferBot(filtre,host)