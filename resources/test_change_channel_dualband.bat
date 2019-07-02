@echo off
echo Setting Channel in OpenPcap Router...

echo[ 
echo Current Channel Setting: 
.\plink.exe -ssh -pw openwrt123 root@192.168.8.1 "iw dev mon0 info | grep channel"

echo[
set /p channel="Enter Channel # to set: "
.\plink.exe -ssh -pw openwrt123 root@192.168.8.1 "monitor_mode.sh mon0 %channel%"
timeout 1 > NUL

echo[
echo Changed Channel Setting: 
.\plink.exe -ssh -pw openwrt123 root@192.168.8.1 "iw dev mon0 info | grep channel"

echo[
set /p dummy="Hit any key to start wireshark ..."

Rem Start wifi packet capture
.\plink.exe -ssh -pw openwrt123 root@192.168.8.1 "tcpdump -i mon0 -U -w - 2>/dev/null" | ("C:\Program Files\Wireshark\Wireshark.exe" "-k" "-i" "-")

