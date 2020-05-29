# WifiSniffing
statistical survey  


nowaday almost 70 percent of people access to the smart phone

in the wifi we have seven mode that we discuss about three important mode which are:  

1- monitor  
2- managed  
3- master  

this link is for standard text file that include the information of vendor such as mac address and the name of company
http://standards-oui.ieee.org/oui.txt

onr of the method for counting number of people with sniffing is that counting their devices that use them
so i change the standard oui file and exploit all the vendor that prodeuce the smart device that people use in a day
for instance laptop or phone or tablet  

first of all install all the dependency with `pip install -r requirements.txt` command

we should keep update and get new things in linux:
```
sudo apt clean  
sudo apt autoremove  
sudo apt-get update --fix-missing  
sudo apt-get full-upgrade --fix-missing  
```

```
sudo apt-get install python3  
sudo apt-get install python3-pip  
sudo apt-get install wireshark  
sudo dpkg-reconfigure wireshark-common  
sudo usermod -a -G wireshark ${USER:-root}  
sudo apt-get install tshark  
sudo pip3 install pyshark  
```

with this link we can find all the type of filtering about the wireless lan
https://www.wireshark.org/docs/dfref/w/wlan.html

```
sudo iwconfig
sudo iwconfig <interface> mode monitor
sudo iwconfig <interface> mode managed
sudo ifconfig <interface> down
sudo ifconfig <interface> up
```
tshark for getting packets  
```
sudo tshark -i <interface> -I
```
`-I` capture in monitor mode, if available

*you need to be a super user to access the `tshark` commadn for capturing packets*

for debugging you can use:
```
sudo lspci
sudo ifconfig
```

```
iw dev
cat /proc/net/wireless
```

all things tested on linux 20.04 focal and i run all the things with normal edup mini wifi dongle that support monitor mode

with this commands we can see all the network interface card that available in host
## LICENSE
MIT  
