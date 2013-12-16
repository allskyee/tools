#!/system/bin/sh

cd /cache/

cat /proc/uptime > $STOR_MON_FILE
cat /sys/block/mmcblk0/stat >> $STOR_MON_FILE
blktrace -d /dev/block/mmcblk0p10 -o system &

wait

#while true
#do
#    for i in 1 2 3 4 5 6 7 8 9 10
#    do
#        cat /sys/block/mmcblk0/stat >> $BOOT_LOG_MMC
#        sleep 1
#    done
#
#    cat /proc/uptime >> $BOOT_LOG_MMC
#
#    cat /sys/block/mmcblk0/mmcblk0p10/stat > /dev/kmsg #system partition
#    /system/bin/busybox head -n 1 /proc/stat > /dev/kmsg
#
#done
