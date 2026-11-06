#!/bin/sh
# Build a minimal ext4 superblock image so `udev --test test/uevent-blkid.txt`
# can exercise the blkid builtin without a real block device.
img="${1:-/tmp/udev-blkid-ext4.img}"
dd if=/dev/zero of="$img" bs=1k count=4 2>/dev/null
# ext4 magic 0xEF53 at byte 0x438 (little-endian: 53 ef)
printf '\x53\xef' | dd of="$img" bs=1 seek=$((0x438)) conv=notrunc 2>/dev/null
# UUID (16 bytes) at 0x468
printf 'udevblkidtest000' | dd of="$img" bs=1 seek=$((0x468)) conv=notrunc 2>/dev/null
# label (16 bytes) at 0x478
printf 'testlabel000000' | dd of="$img" bs=1 seek=$((0x478)) conv=notrunc 2>/dev/null
echo "wrote $img"
