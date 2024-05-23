#! /usr/bin/bash
set -e

read -p "EXTRAVERSION Tag: " tagname

make mrproper 
lsmod > /tmp/lsmod.now
make LSMOD=/tmp/lsmod.now localmodconfig

scripts/config --disable SYSTEM_TRUSTED_KEYS
scripts/config --disable SYSTEM_REVOCATION_KEYS
scripts/config --disable CONFIG_DEBUG_INFO_BTF

time make CC="ccache gcc" -j40 EXTRAVERSION=-$tagname

sudo make modules install

#sudo make install (holding for now)
