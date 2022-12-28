#from scapy.all import *
import scapy.all as scapy

def pkt_callback(pkt):
   pkt_cnt = 0
   layer = pkt.getlayer(pkt_cnt)
   if layer.haslayer(scapy.Raw) and layer.haslayer(scapy.IP):

      tcpdata = bytes(pkt.payload)
      datalen = len(tcpdata)
      #print(tcp_data)
      #print(scapy.hexdump(tcp_data))
      print(datalen)
      tcpdatas = []
      for i in range (10):
         tcpdatas.append(f"{tcpdata[i]:0{2}x}")

      tcp_data = layer.getlayer(scapy.Raw).load

      tcpdatstr = scapy.hexstr(tcp_data)
      tcpdatstra = tcpdatstr.split()

      for i in range (10):
         print(tcpdatstra[i])
         #print(tcpdatas[i])
         #print(tcpdata[i])

#Start Main
scapy.sniff(iface="eth0", prn=pkt_callback, filter="tcp", store=False, count=1)
