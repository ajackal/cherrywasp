# cherry-wasp README
#
# This program is designed as a probe request and beacon sniffer. You must have a monitor-mode NIC interface setup.
#
# Mode 0 will sniff all probe requests and the BSSID (MAC address) that is probing and save them to a .csv file. You can filter by 
# a specific BSSID with the "-b" option.
# 
# Mode 1 will sniff and record all beacons that the NIC can hear and their associated BSSID saving them to a .csv file.
#
# Mode 2 will sniff and record both beaconds and probe requests. The filter option "-b" will not currently work with Mode 2.
#
# This program is desgined for network and target reconiassance to facilitate authorized white-hat wireless pen-testers or
# enthusiasts testing on their own network or lab enviornment.
