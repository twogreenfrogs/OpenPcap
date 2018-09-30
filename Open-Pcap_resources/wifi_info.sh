#!/bin/bash
interface="mon0"

Mode=$(iwconfig $interface 2> /dev/null | grep "802.11" | awk '{print $3}')
#[[ "$Mode" != *"802.11"* ]] && echo "No WiFi Device" && exit 1

NumOfBand=$(iwlist $interface freq 2> /dev/null | egrep "Channel 11|Channel 36" | wc -l)
#[ "$?" -ne 0 ] && echo "No WiFi Device" && exit 1

#micRouter has fixed internal wifi interface.
#just return hardcoded values

Mode="802.11 bgn"
NumOfBand="1"
if [ "$NumOfBand" == "1" ]
then
    Band="2.4G"
elif [ "$NumOfBand" == "2" ]
then
    Band="2.4G/5G"
else
    echo "No WiFi Device"
    exit 1
fi

echo "${Mode}, ${Band}"
exit 0

