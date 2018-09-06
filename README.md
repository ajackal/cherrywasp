# cherry-wasp README #

![Travis CI Build Status](https://travis-ci.org/ajackal/cherry-wasp.svg?branch=master)

## Intent ##

This program is desgined for network and target reconiassance to facilitate authorized wireless penetration tests or enthusiasts testing on their own network or lab enviornment.

This program is designed as a probe request and beacon sniffer. You must have a monitor-mode NIC interface setup.

# Usage #

Mode 0 will sniff all probe requests and the BSSID (MAC address) that is probing and save them to a .csv file. You can filter by a specific BSSID with the "-b" option.
 
Mode 1 will sniff and record all beacons that the NIC can hear and their associated BSSID saving them to a .csv file.

Mode 2 will sniff and record both beaconds and probe requests. The filter option "-b" will not currently work with Mode 2.


## License ##

cherry-wasp is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.

cherry-wasp is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with cherry-wasp. If not, see the gnu.org web site.
