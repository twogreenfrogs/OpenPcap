#!/bin/bash

# when reserting wifi dongle, phy num changes
PHY=$(iw phy | grep Wiphy | cut -d ' ' -f2)

if [[ $PHY != *"phy"* ]]
then
    >&2 echo "cannot find wifi interface"
    exit 1
fi

iw dev mon0 del > /dev/null 2>&1
iw phy $PHY interface add mon0 type managed > /dev/null 2>&1
ifconfig mon0 up
iwlist mon0 scan > /dev/null
iwlist mon0 scan > /dev/null
iwlist mon0 scan | egrep "Address|Channel|Frequency|Quality|ESSID|IE" | grep -v Unknown > site_survey.txt

sed -i "s/Cell/\n SSID/" site_survey.txt
sed -i "s/         //" site_survey.txt
cat site_survey.txt

rm -rf site_survey.txt
ifconfig mon0 down
iw dev mon0 del
exit 0
