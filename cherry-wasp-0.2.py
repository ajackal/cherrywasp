from scapy.all import *
import optparse
from termcolor import colored


slist = []
blist = []


def p_probe_req(pkt):
    with open("ssid_requests.csv", "a") as r:
        if pkt.haslayer(Dot11ProbeReq):
            essid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")
            bssid = pkt.sprintf("%Dot11.addr2%")
            no_broadcast = False
            if essid != "":
                no_broadcast = True
            if no_broadcast is True and essid not in slist:
                slist.append(essid)
                print "[+] Probe Request for {0} from <{1}>".format(colored(essid, 'green'), colored(bssid, 'red'))
                r.write("{0},{1}\n".format(bssid, essid))


def p_beacon(pkt):
    with open("ssid_beacons.csv", "a") as b:
        if pkt.haslayer(Dot11Beacon):
            essid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")
            bssid = pkt.sprintf("%Dot11.addr2%")
            no_broadcast = False
            if essid != "":
                no_broadcast = True
            if no_broadcast is True and essid not in blist:
                blist.append(essid)
                print "[+] <{0}> is beaconing as {1}".format(colored(bssid, 'red'), colored(essid, 'green'))
                b.write("{0},{1}\n".format(bssid, essid))


def p_both(pkt):
    with open("ssid_beacons.csv", "a") as b:
        if pkt.haslayer(Dot11Beacon):
            essid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")
            bssid = pkt.sprintf("%Dot11.addr2%")
            no_broadcast = False
            if essid != "":
                no_broadcast = True
            if no_broadcast is True and essid not in blist:
                blist.append(essid)
                print "[+] <{0}> is beaconing as {1}".format(colored(bssid, 'red'), colored(essid, 'green'))
                b.write("{0},{1}\n".format(bssid, essid))
    with open("ssid_requests.csv", "a") as r:
        if pkt.haslayer(Dot11ProbeReq):
            essid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")
            bssid = pkt.sprintf("%Dot11.addr2%")
            no_broadcast = False
            if essid != "":
                no_broadcast = True
            if no_broadcast is True and essid not in slist:
                slist.append(essid)
                print "[+] Probe Request for {0} from <{1}>".format(colored(essid, 'green'), colored(bssid, 'red'))
                r.write("{0},{1}\n".format(bssid, essid))


def main():
    parser = optparse.OptionParser('usage for print probe ' + '-m <scanning mode> ' + '-i <interface> ' + '-b <filter bssid> ')
    parser.add_option('-m', dest='mode', type='string', help='0=probe requests, 1=beacons, 2=both')
    parser.add_option('-i', dest='iface', type='string', help='specify interface to listen on')
#    parser.add_option('-b', dest='bssid', type='string', help='specify target bssid to filter <optional>')
    (options, args) = parser.parse_args()


    if options.iface is None:
        print "[!] must define an interface with <-i>!"
        print parser.usage
        exit(0)
    else:
        conf.iface = options.iface

    if options.bssid is None:  # this line is added for future development of bssid filtering
        if options.mode is "0":
            sniff(prn=p_probe_req)
        if options.mode is "1":
            sniff(prn=p_beacon)
        if options.mode is "2":
            sniff(prn=p_both)
# This section is to allow filtering by bssid;
# still haven't gotten it to work correctly
#
#    if options.bssid is not None:
#        if options.mode is "0":
#            fbssid = str("%Dot11.addr2% " + options.bssid)
#            sniff(filter="fbssid" prn=p_probe_req)
#        else:
#            print "[!] must use mode 0 when filtering by BSSID"
#            exit(0)
    else:
        print "[!] must define a mode with <-m>!"
        print parser.usage
        exit(0)

if __name__ == "__main__":
    main()

