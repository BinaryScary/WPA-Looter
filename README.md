# WPA-Looter
Parse PCAP/PCAPNG files for WPA specific loot (PMK,PMKID)

## Usage
```
(i)BinaryScary@HackBook:WPA-Looter$ ./wpa-looter.py output-07.cap
100it [00:00, 47.71it/s]
150it [00:00, 68.23it/s]
200it [00:00, 85.54it/s]

[-] Access points with PMKs retrieved from EAPOL 4-Way Handshake
ESSID-Example1    1A:35:70:23:9F:07
ESSID-Example2    1A:35:70:23:9F:08
ESSID-Example3    1A:35:70:23:9F:09

[-] Access points with PMKIDs retrieved from association packets (Handshake Message One)
ESSID-Example1    1A:35:70:23:9F:07
ESSID-Example2    1A:35:70:23:9F:08
ESSID-Example3    1A:35:70:23:9F:09
```
