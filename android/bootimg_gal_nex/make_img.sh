#!/bin/bash

cd initrd
find . -path "*.swp" -prune -o -name "*" -print | cpio -o -H newc | gzip > ../boot-new.img-ramdisk.gz
cd ..


#mkbootimg --kernel zImage.sqfs_blktr --ramdisk boot-new.img-ramdisk.gz --base 80000000 --pagesize 2048 -o boot-new.img
mkbootimg --kernel zImage.sqfs_blktr_delacct --ramdisk boot-new.img-ramdisk.gz --base 80000000 --pagesize 2048 -o boot-new.img
