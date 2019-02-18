#!/bin/bash

# turn off wifi when shutdown down
echo default-on > /sys/class/leds/gl-usb150\:green\:wlan/trigger 2> /dev/null
 echo 0 > /sys/class/leds/gl-usb150\:wlan/brightness 2> /dev/null
poweroff
