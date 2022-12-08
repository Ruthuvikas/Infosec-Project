from scapy.all import *
from yacryptopan import CryptoPAn
import random

cp = CryptoPAn(b'32-char-str-for-AES-key-and-pad.')

def has_ip(pkt):
  if "IP" in pkt:
    return 1
  else:
    return 0

def randomizer(pks):
  if(has_ip(pks)):
    for i in range(len(pks)):
      src = pks[i][IP].src
      dest = pks[i][IP].dst

      if src:
        rnd_src = ""
        for j in range(4):
          num = random.SystemRandom().randint(1, 254)
          rnd_src += str(num)
          if j != 3:
            rnd_src += "."
        pks[i][IP].src = str.encode(rnd_src)

      if dest:
        rnd_dest = ""
        for k in range(4):
          num = random.SystemRandom().randint(1, 254)
          rnd_dest += str(num)
          if k != 3:
            rnd_dest += "."
        pks[i][IP].dst = str.encode(rnd_dest)

def prefanon(pks):
  if(has_ip(pks)):
    for i in range(len(pks)):
      src = pks[i][IP].src
      dest = pks[i][IP].dst

      if src:
        new_src = cp.anonymize(src)
        pks[i][IP].src = str.encode(new_src)

      if dest:
        new_dest = cp.anonymize(dest)
        pks[i][IP].dst = str.encode(new_dest)

def prefanon_tcpdump(pks):
  for packet in pks:
    if(has_ip(packet)):
      source_ip = packet.getlayer(IP).src
      destination_ip = packet.getlayer(IP).dst

      if source_ip:
        new_src = cp.anonymize(source_ip)
        packet.getlayer(IP).src = str.encode(new_src)

      if destination_ip:
        new_dst = cp.anonymize(destination_ip)
        packet.getlayer(IP).dst = str.encode(new_dst)
      

packets = rdpcap("outside.tcpdump")
prefanon_tcpdump(packets)
wrpcap("outside-pref.pcap", packets)
