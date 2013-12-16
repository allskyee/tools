#!/bin/bash

#BOOT -> /dev/block/mmcblk0p9 (8,192)
#CACHE -> /dev/block/mmcblk0p19 (2,688,000)
#RECOVERY -> /dev/block/mmcblk0p10 (8,192)
#SYSTEM -> /dev/block/mmcblk0p20 (3,584,000)
#USERDATA -> /dev/block/mmcblk0p21 (23,203,840)

#cp arch/arm/boot/zImage .
#cp /home/allsky/android/SHV-E300S/kernel/arch/arm/boot/zImage boot-new.img-kernel
cd initrd
find . | cpio -o -H newc | gzip > ../boot-new.img-ramdisk.gz
cd ..
./mkbootimg --kernel zImage.e2compr --ramdisk boot-new.img-ramdisk.gz -o boot-new.img --base 0x48000000 --pagesize 2048
#tar cvf gals4_bootimg.tar boot.img
#echo created gals4_bootimg.tar

#adb push boot-new.img /sdcard/0/test_dev/
