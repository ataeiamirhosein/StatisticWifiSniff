
#<author amirhosein ataei
#important github repo
# thanks from https://github.com/statisticsniff/howmanypeoplearearound
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


import pandas as pd
import time
import os
import webbrowser
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
#import all the needed library such as color, plot, time and os
from colorama import Fore, Back, Style
from pick import pick
from getpass import getpass
from subprocess import Popen, PIPE


#initializing section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


colorama.init()
#set the specific background and foreground color to black and white for seprating reason 
print(Fore.WHITE + Back.BLACK)
#show the logo of package in a red color
print(Fore.RED + '\n        |         |  _)      |  _)      \n    __| __|  _` | __| |  __| __| |  __| \n  \__ \ |   (   | |   |\__ \ |   | (    \n  ____/\__|\__,_|\__|_|____/\__|_|\___| \n                                        \n            _)  _|_)            _)  _|  _| \n    \  \   / | |   |   __| __ \  | |   |   \n   \ \  \ /  | __| | \__ \ |   | | __| __| \n    \_/\_/  _|_|  _| ____/_|  _|_|_|  _|   \n')
print(Fore.MAGENTA + '          github.com/ataeiamirhosein\n------------------------------------------------------\n- performance depend your wireless card \n- connect internet and be sure support monitor mode ')
#reset the colors to the black and white and continue
print(Fore.WHITE + Back.BLACK)
print("loading files take a moments connecting ...\n")
#getting a oui file from the valid github repo that took from ieee source
urlgit = 'https://raw.githubusercontent.com/statisticsniff/howmanypeoplearearound/master/oui.txt'
#send a download request to the server and save in object req
req = requests.get(urlgit, allow_redirects=True)
#license agreement and select process menu
inp = input('> your password needed only using for root commands to continue.\n> be careful to enter inputs correct.\n\n* do you continue?\n[yes] continue, [no] stop\n' + Fore.RED + '-> ')
if inp == 'yes':
    #reset the colors again and start the initializing processes
    print(Fore.YELLOW + "\n-->running process ...\n")
    print(Fore.WHITE + Back.BLACK)
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
procon = Popen("sudo -S chmod 777 oui.txt".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outon = procon.communicate(password.encode())


#reading vendors info section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


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
#correcting the format of vendor names
for h in range (0, len(vendor_name)):
    tempo = vendor_name[h]
    tempo = tempo.replace('\n', '')
    vendor_name[h] = tempo
#fill other negligible vendor with unknown
UNIQUE_VENDOR = numpy.unique(vendor_name)
UNIQUE_VENDOR = numpy.append(UNIQUE_VENDOR, "UNKOWN")


#sniffing packet section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


proctw = Popen("sudo -S touch result.html".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outtw = proctw.communicate(password.encode())
#
procth = Popen("sudo -S touch cap.pcapng".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outth = procth.communicate(password.encode())
#
procfo = Popen("sudo -S chmod 777 cap.pcapng".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outfo = procfo.communicate(password.encode())
#
procfi = Popen("sudo -S chmod 777 result.html".split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
outfi = procfi.communicate(password.encode())
#
adapters = netifaces.interfaces()
#select the wireless adapter for sniffing
title = 'choose the adapter you want to use: '
option, index = pick(adapters, title)
#getting a time in start point for measuring time complexity
total_time = 0
start_time = time.time()
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
print(Fore.YELLOW)
print("\n-->scaning frames take a moments ...")
print(Fore.WHITE + Back.BLACK)
#
procsi = Popen(["tshark", "-i", option, "-I", "-a", "packets:128", "-w", "cap.pcapng", "-F", "pcapng"], stdout=PIPE, stderr=PIPE)
outsi = procsi.communicate()
#
cap = pyshark.FileCapture('cap.pcapng')


#filtering probes section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


ssid_list = []
mac_list = []
rssi_list = []
#
countero = 0
#capturing wireless signal from adapter in monitor mode and filtering all the beacon feames for processing
for packet in cap:
    try:
        #filter for all management frames
        if packet.wlan.fc_type == '0':
            ssid = packet.layers[3].wlan_ssid
            mac = packet.wlan.sa
            rssi = packet.wlan_radio.signal_dbm
            #ssid is a important parameter so we detect base on probes that has ssid
            if ssid != 'SSID: ' and len(ssid) <= 32:
                if ssid.isascii():
                    try:
                        ssid_list.append(ssid)
                        mac_list.append(mac)
                        rssi_list.append(rssi)
                    except UnicodeDecodeError:
                        pass
                countero = countero + 1
                #debug for detecting the working of ssid detect
    except:
        pass
#finish the search of data from captured packets
print(Fore.YELLOW)
print("\n-->captured " + str(countero) + " probes")
print(Fore.WHITE + Back.BLACK)


#exploiting crucial information section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


unique_mac = numpy.unique(mac_list)
unique_ssid = numpy.unique(ssid_list)
#
print("\nunique ssid: " + str(unique_ssid))
#converting the format of macs
for x in range (0, len(unique_mac)):
    temp = unique_mac[x]
    temp = temp.replace(':', '')
    temp = temp.upper()
    unique_mac[x] = temp[0:6]
#
print("\nunique mac: " + str(unique_mac) + "\n")
#
find = []
number = []
countert = 0
#finding vendor name index from fined macs
for yo in range (0, len(unique_mac)):
    for zo in range (0, len(vendor_mac)):
        if unique_mac[yo] == vendor_mac[zo]:
            #finding a mac that exist in the list of ieee macs
            find.append(vendor_mac[zo])
            number.append(zo)
            countert = countert + 1
#print the find variable which contain a fined mac that exist in a standard list
print(find)
#
names = []
for w in range (0, len(number)):
    names.append(vendor_name[number[w]])  
#
print(names)


#indexing section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


indexo = []
indext = []
#
for l in range(0, len(unique_ssid)):
    for k in range(0, len(ssid_list)):
        if unique_ssid[l] == ssid_list[k]:
            indexo.append(l)
            indext.append(k)
#
# unique_indexo = numpy.unique(indexo)
#
print(unique_indexo)
print(indext)
#
indexth = []
#
for n in range(0, len(find)):
    for m in range(0, len(unique_mac)):
        if find[n] == unique_mac[m]:
            indexth.append(m)
#
print(indexth)


#innovate a method for seprating list of devices that use by people getting from gsm source to another equipment like access points with filtering
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


devices = ['Motorola Mobility LLC, a Lenovo Company',
           'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD',
           'HUAWEI TECHNOLOGIES CO.,LTD',
           'Microsoft Corporation',
           'HTC Corporation',
           'Samsung Electronics Co.,Ltd',
           'BlackBerry RTS',
           'LG Electronics (Mobile Communications)',
           'Apple, Inc.',
           'OnePlus Tech (Shenzhen) Ltd',
           'Xiaomi Communications Co Ltd',
           'zte corporation',
           'Nokia Corporation',
           'Sony Mobile Communications Inc',
           'Google, Inc.',
           'Dell Inc.',
           'Hewlett Packard',
           'Amazon Technologies Inc.',
           'Intel Corporate',
           'Lenovo',
           'Liteon Technology Corporation']
#detecting the person numbers from the statistic of vendor that produce phone or tablet or laptop which used by people
v = 0
for q in range(0, len(names)):
    for w in range (0, len(devices)):
        if names[q] == devices[w]:
            v = v + 1
#printing the number of detect near people
print(Fore.BLUE)
if v == 0:
    print("> no active person around you")
else:
    print('> about ' + Fore.RED + str(v) + Fore.BLUE + ' active person available near you!')


#time complexity section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


temp_time = time.time()
total_time = temp_time - start_time
#calculate tic toc time
print(Fore.MAGENTA + '\n> time complexity= ' + str(total_time) + " sec")
print(Fore.GREEN)


#plot section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


s = pd.Series([1, 2, 3, 4])
fig, ax = plt.subplots()
s.plot.bar()
fig.savefig('plot.png')


#statistic out file section
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

 
filetw = open('result.html', 'w')
filetw.write("""<!DOCTYPE html>\n<html>\n<head>\n<title>statistic_wifi_sniff</title>\n</head>\n<body>\n<div align='center'>\n<h2>statistic wifi sniff</h2>\n<hr>\n<img src='plot.png'>\n<p><font color='green'>-the closer it is to zero, the stronger the signal is. </font><font color='purple'>so it is nearest.</font></p>\n<br>\n<hr>\n<p><font color='blue'>> total physical address near you = </font>""" + str(unique_mac) + """<font color='red'> that probably active person = </font>""" + str(find) + """</p>\n<p><font color='brown'>> the name of people = </font>""" + str(unique_ssid) + """</p>\n<p><font color='brown'>> name of equipment vendor = </font>""" + str(names) + """</p>\n<hr>\n<p>-see <a href="https://github.com/ataeiamirhosein/StatisticWifiSniff/blob/master/devices.txt" target="_blank">LIST</a> of sorted vendor that produce equipment that used by people such as phone, tablet and laptop.</p><hr>\n<p><a href="https://github.com/ataeiamirhosein" target="_blank">amirhosein ataei</a><p>\n</div>\n</body>\n</html>""")
filetw.close()
#now we can see all the data in result file for devices and in cap file about capture frame also oui file
print('\n* see all detection in result file that will be open automatically\n\n* all operations was succesfull so stop *\n' + Style.RESET_ALL)
#getting the usename of linux os
u = os.popen('whoami')
user = u.read()
#we should change the permission of group in os to access the html out result file
final = Popen(["sudo", "-S", "chown", "-v", user.strip(), "result.html"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
ofinal = final.communicate(password.encode())
#open the out file via browser automatically
urlhtml = 'result.html'
webbrowser.open(urlhtml, new=2)


#end of program>
#reference
# thanks from https://macaddress.io/
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
