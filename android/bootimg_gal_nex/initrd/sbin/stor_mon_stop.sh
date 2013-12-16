#!/system/bin/sh

cd /cache/

cat /proc/uptime >> $STOR_MON_FILE
cat /sys/block/mmcblk0/stat >> $STOR_MON_FILE

stop stor_mon
