#!/usr/bin/env python3
import pyshark
import sys
from tqdm import tqdm

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("Provide packet capture file")
        quit()

    # parse EAPOL handshakes
    eapol = pyshark.FileCapture(sys.argv[1],display_filter="eapol")
    messages = {2:set(),3:set(),4:set()}
    pmks = set()
    # only need packets 2,3 or 3,4 from the same handshake to crack PMK 
    for pkt in tqdm(eapol):
        source = pkt['wlan'].sa
        dest = pkt['wlan'].da
        try:
            messnum = pkt['eapol'].wlan_rsna_keydes_msgnr
        except AttributeError:
            continue

        # probably a better way to id handshakes, then AP mac
        if messnum == '2':
            messages[2].add(dest)
            if dest in messages[3]:
                pmks.add(dest)
        if messnum == '3':
            messages[3].add(source)
            if source in messages[2]:
                pmks.add(source)
            if source in messages[4]:
                pmks.add(source)
        if messnum == '4':
            messages[4].add(dest)
            if dest in messages[3]:
                pmks.add(dest)
    eapol.close()

    # parse EAPOL handshake message 1 for pmkids
    eapol_pmkid = pyshark.FileCapture(sys.argv[1],display_filter="eapol && wlan.rsn.ie.pmkid")
    pmkids = set()
    for pkt in tqdm(eapol_pmkid):
        pmkids.add(pkt['wlan'].sa)
    eapol_pmkid.close()

    # check for no loot
    if len(pmkids) == 0 and len(pmks) == 0:
        print('[-] Packets do not contain loot')
        quit()

    # get ESSIDS from beacon packets
    bssids = set()
    bssids.update(pmkids)
    bssids.update(pmks)
    # is there a limit to display filter size?
    dfilter = "wlan.fc.type_subtype==0x08 && ( wlan.sa==" + " || wlan.sa==".join(bssids) + ")"
    beacons = pyshark.FileCapture(sys.argv[1],display_filter=dfilter)
    essids = {}
    for pkt in tqdm(beacons):
        bssid = pkt['wlan'].sa
        try:
            ssid = pkt['wlan.mgt'].wlan_ssid 
        except AttributeError:
            continue
        if pkt['wlan.mgt'].wlan_ssid == 'SSID: ':
            continue
        essids[bssid] = ssid

        if len(essids) == len(bssids):
            break

    beacons.close()

    # print loot
    if len(pmks) > 0:
        print('[-] Access points with PMKs retrieved from EAPOL 4-Way Handshake')
        for ap in set(pmks):
            print(essids.get(ap,"(no beacons found for AP)"), end='')
            print(f'    {ap}')
        print()

    if len(pmkids) > 0:
        print('[-] Access points with PMKID retreived from association packets (Handshake Message One)')
        for ap in set(pmkids):
            print(essids.get(ap,"(no beacons found for AP)"), end='')
            print(f'    {ap}')

