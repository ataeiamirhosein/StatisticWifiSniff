#author amirhosein ataei
import difflib
import pyshark
import numpy
import itertools
import matplotlib.pyplot as plt
import time
import netifaces
import curses
import requests
import sys
import click
import colorama
#import all the needed library
from colorama import Fore, Back, Style
from pick import pick
from getpass import getpass
from subprocess import Popen, PIPE
#initialize the color library
colorama.init()
#set the specific background and foreground color to black and white for seprating reason 
print(Fore.WHITE + Back.BLACK)
#show the logo of package in a red color
print(Fore.RED + '\n      |         |  _)      |  _)      \n  __| __|  _` | __| |  __| __| |  __| \n\__ \ |   (   | |   |\__ \ |   | (    \n____/\__|\__,_|\__|_|____/\__|_|\___| \n                                      \n          _)  _|_)            _)  _|  _| \n\ \  \   / | |   |   __| __ \  | |   |   \n \ \  \ /  | __| | \__ \ |   | | __| __| \n  \_/\_/  _|_|  _| ____/_|  _|_|_|  _|   \n\n' + Fore.MAGENTA + '        github.com/ataeiamirhosein')
#reset the colors to the black and white and continue
print(Fore.WHITE + Back.BLACK)
print("loading files ...\n")
#getting a oui file from the valid source
urlieee = 'http://standards-oui.ieee.org/oui.txt'
#send a download request to the server and save in object req
req = requests.get(urlieee, allow_redirects=True)
#license agreement and reminder
inp = input('- your password needed only using for root commands to continue.\n> be careful to enter inputs correct.\n* do you continue?\n\n[yes] continue, [no] stop\n' + Fore.RED + '-> ')
if inp == 'yes':
    #reset the colors again and start the initializing processes
    print(Fore.WHITE + Back.BLACK)
    print("\nrunning process ...")
    pass
elif inp == 'no':
    #stop the process and close the program by choosing item no 
    print('stopped and goodbye.')
    print(Style.RESET_ALL)
    exit()
else:
    #stop the process and close the program by prevent any bug because input was not correct
    print('exit for wrong input!')
    print(Style.RESET_ALL)
    exit()
#receive the password for root reason commands
password = getpass("for root reason enter password: ")
#creating the oui text file for saving all the vendor information with popen command and use subprocess library
procze = Popen("sudo -S touch oui.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outze = procze.communicate(password.encode())
#
procon = Popen("sudo -S chmod a=rw oui.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outon = procon.communicate(password.encode())
#
fileon = open('oui.txt', 'wb')
fileon.write(req.content)
fileon.close()
#
oui = open('oui.txt', 'r')
#
vendor_mac = []
vendor_name = []
#
for line in oui:
    if "(base 16)" in line:
        fields = line.split("\t")
        vendor_mac.append(fields[0][0:6])
        vendor_name.append(fields[2])
#
UNIQUE_VENDOR = numpy.unique(vendor_name)
UNIQUE_VENDOR = numpy.append(UNIQUE_VENDOR, "UNKOWN")
#
proctw = Popen("sudo -S touch result.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outtw = proctw.communicate(password.encode())
#
procth = Popen("sudo -S touch cap.pcapng".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outth = procth.communicate(password.encode())
#
procfo = Popen("sudo -S chmod a=rw cap.pcapng".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outfo = procfo.communicate(password.encode())
#
procfi = Popen("sudo -S chmod a=rw result.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outfi = procfi.communicate(password.encode())
#
adapters = netifaces.interfaces()
print(adapters)
#
title = 'choose the adapter you want to use: '
option, index = pick(adapters, title)
#
print(option)
#
a = Popen(["sudo", "-S", "ifconfig", option, "down"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
oa = a.communicate(password.encode())
#
b = Popen(["sudo", "-S", "iwconfig", option, "mode", "monitor"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
ob = b.communicate(password.encode())
#
c = Popen(["sudo", "-S", "ifconfig", option, "up"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
oc = c.communicate(password.encode())
#
d = Popen("iwconfig", stdin=PIPE, stdout=PIPE, stderr=PIPE)
od = d.communicate()
print(od)
#
procsi = Popen(["tshark", "-i", option, "-I", "-a", "packets:250", "-w", "cap.pcapng", "-F", "pcapng"], stdout=PIPE, stderr=PIPE)
outsi = procsi.communicate()
#
cap = pyshark.FileCapture('cap.pcapng')
#
ssid_list = []
mac_list = []
rssi_list = []
#
print("\nsearching frames...")
#
counter = 0
#capturing wireless signal from adapter in monitor mode and filtering all the beacon feames for processing
for packet in cap:
    try:
        if packet.wlan.fc_type_subtype == '8':
            ssid = packet.layers[3].wlan_ssid
            mac = packet.wlan.sa
            rssi = packet.wlan_radio.signal_dbm
            #
            if ssid != 'SSID: ' and len(ssid) <= 32:
                if ssid.isascii():
                    try:
                        ssid_list.append(ssid)
                        mac_list.append(mac)
                        rssi_list.append(rssi)
                    except UnicodeDecodeError:
                        pass
                counter = counter + 1
                print(counter)
                #debug for detecting the working of ssid detect
    except:
        pass
#finish the search of data from captured packets
print(ssid_list)
#
print("\ncaptured " + str(counter) + " probes")
#
print(mac_list)
#
unique_mac = numpy.unique(mac_list)
unique_ssid = numpy.unique(ssid_list)
#
print("\nmacs: " + str(unique_mac))
#
filetw = open('result.txt', 'w')
filetw.write("macs -> "+str(unique_mac)+"\nssids ->"+str(unique_ssid))
filetw.close()
#finding vendor name from fined macs

for x in range (0, len(unique_mac)):
    temp = unique_mac[x]
    temp = temp.replace(':', '')
    temp = temp.upper()
    unique_mac[x] = temp[0:6]

print(unique_mac)

co = 0

for y in range (0, len(vendor_mac)):
    if difflib.SequenceMatcher(None, unique_mac[0], vendor_mac[y]).ratio() >= 0.83:
        co = co + 1

print(co)
#i innovate a method for seprating devices that use by people from another like access points with filter by specific vendor
devices = ['Motorola Mobility LLC, a Lenovo Company',
           'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD',
           'HUAWEI TECHNOLOGIES CO.,LTD',
           'Microsoft Corporation',
           'HTC Corporation',
           'SAMSUNG ELECTRONICS Co.,Ltd',
           'BlackBerry RTS',
           'LG Electronics (Mobile Communications)',
           'Apple, Inc.',
           'OnePlus Technology (Shenzhen) Co., Ltd',
           'Xiaomi Communications Co Ltd',
           'zte corporation',
           'Nokia Corporation',
           'Sony Mobile Communications Inc']
#now we can see all the data in result file for devices and in cap file about capture frame also oui file
print(Fore.GREEN + '* operations was succesfull\n> you can see all detection in the result file' + Style.RESET_ALL)
#end of program
