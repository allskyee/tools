#!/bin/bash

./linux-3.9.11/linux rootfstype=hostfs rw mem=256M init=`pwd`/uml-init.sh umid=uml ROOTDIR=`pwd`
