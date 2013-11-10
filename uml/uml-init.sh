#!/bin/bash

mount -t proc none /proc
mount -t sysfs none /sys
#echo "4 4 1 7" > /proc/sys/kernel/printk
cat /proc/kmsg > $ROOTDIR/uml_printk &

cd $ROOTDIR
exec /bin/bash --rcfile $ROOTDIR/uml-init.rc
