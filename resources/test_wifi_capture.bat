Rem Put wifi interface into monitor mode
.\plink.exe -ssh -pw openwrt123 root@192.168.8.1 "monitor_mode.sh mon0 1"
timeout 1 > NUL

Rem Start wifi packet capture
.\plink.exe -ssh -pw openwrt123 root@192.168.8.1 "tcpdump -i mon0 -U -w - 2>/dev/null" | ("C:\Program Files\Wireshark\Wireshark.exe" "-k" "-i" "-")