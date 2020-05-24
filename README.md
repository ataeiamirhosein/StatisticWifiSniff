# WifiSniffing
statistical survey  

in the wifi we have seven mode that we discuss about three important mode which are:  

1- monitor  
2- managed  
3- master  

this link is for standard text file that include the information of vendor such as mac address and the name of company
http://standards-oui.ieee.org/oui.txt

onr of the method for counting number of people with sniffing is that counting their devices that use them
so i change the standard oui file and exploit all the vendor that prodeuce the smart device that people use in a day
for instance laptop or phone or tablet  

first of all we should keep update and get new things in linux:
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

```
sudo iwconfig
sudo iwconfig <interface> mode monitor
sudo iwconfig <interface> mode managed
sudo ifconfig <interface> down
sudo ifconfig <interface> up
```
tshark for getting packets  
```
tshark -i <interface> -I
```
`-I` capture in monitor mode, if available

for debugging you can use:
```
lspci
```
