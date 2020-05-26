import pyshark
import numpy
import itertools
import matplotlib
import time
import netifaces
import curses

from pick import pick
from getpass import getpass
from subprocess import Popen, PIPE

print("Statistic Wifi Sniff")

oui = open('oui.txt', 'r')

vendor_mac = []
vendor_name = []

for line in oui:
    if "(base 16)" in line:
        fields = line.split("\t")
        vendor_mac.append(fields[0][0:6])
        vendor_name.append(fields[2])

adapters = netifaces.interfaces()
print(adapters)

title = 'choose the adapter you want to use: '
option, index = pick(adapters, title)

print(option)

password = getpass("for root reason enter password: ")

print("\nstarting service ...")

procze = Popen("sudo -S touch out.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outze = procze.communicate(password.encode())

procon = Popen("sudo -S touch cap.pcapng".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outon = procon.communicate(password.encode())

proctw = Popen("sudo -S chmod a=rw cap.pcapng".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outtw = proctw.communicate(password.encode())

procth = Popen("sudo -S chmod a=rw out.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outth = procth.communicate(password.encode())

procfo = Popen(["tshark", "-i", option, "-I", "-a", "duration:20", "-w", "cap.pcapng", "-F", "pcapng"], stdout=PIPE, stderr=PIPE)
outfo = procfo.communicate()

print(outfo)

cap = pyshark.FileCapture('cap.pcapng')

ssid_list = []
mac_list = []
rssi_list = []

counter = 0

print("\nsearching frames...")

for packet in cap:
    try:
        if packet.wlan.fc_type_subtype == '4':
            ssid = packet.layers[3].wlan_ssid
            mac = packet.wlan.sa
            rssi = packet.wlan_radio.signal_dbm
            if ssid != 'SSID: ' and len(ssid) <= 32:
                if ssid.isascii():
                    try:
                        ssid_list.append(ssid)
                        mac_list.append(mac)
                        rssi_list.append(rssi)
                    except UnicodeDecodeError:
                        pass
                counter = counter + 1
    except:
        pass

print("\ncaptured " + str(counter) + " probes")

print(mac_list)

unique_mac = numpy.unique(mac_list)

print("\nmacs: " + str(unique_mac))

file = open('out.txt', 'w')
file.write(str(unique_mac))
file.close()
