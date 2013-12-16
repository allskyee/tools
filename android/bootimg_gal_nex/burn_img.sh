#!/bin/bash

if [ "$1" == "m" ]; then
    ./make_img.sh
fi

COPY_DIR=/data/media/0/test_dev
IMG_FILE=boot-new.img

adb push $IMG_FILE $COPY_DIR/$IMG_FILE
adb shell dd if=$COPY_DIR/$IMG_FILE of=/dev/block/mmcblk0p7

adb reboot
