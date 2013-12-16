#!/system/bin/sh

cd /cache/

cat /proc/uptime > $CPU_MON_FILE
cat /proc/stat >> $CPU_MON_FILE

while true
do
    sleep 1
    cat /proc/uptime >> $CPU_MON_FILE
    cat /proc/stat >> $CPU_MON_FILE
done
