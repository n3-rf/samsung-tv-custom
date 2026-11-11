#!/bin/bash
# Write a Kant USB image to a whole external disk. Destructive by design.
#
# usage:  sudo CONFIRM_WRITE=YES bash write_usb.sh IMAGE DISK
#         DISK is a whole-disk identifier such as disk8 (not disk8s1).
#
# Refuses internal disks, partial disks, missing confirmation and disks
# smaller than the image.
set -euo pipefail

IMG="${1:?usage: write_usb.sh IMAGE DISK}"
DISK="${2:?usage: write_usb.sh IMAGE DISK}"

[ "${CONFIRM_WRITE:-}" = "YES" ] || {
  echo "refusing: set CONFIRM_WRITE=YES to confirm the erase"; exit 1; }
[[ "$DISK" =~ ^disk[0-9]+$ ]] || {
  echo "refusing: '$DISK' is not a whole-disk identifier (disk0, disk8, ...)"; exit 1; }
[ -f "$IMG" ] || { echo "refusing: image not found: $IMG"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "refusing: run with sudo"; exit 1; }

info="$(diskutil info "$DISK")"
grep -q "Whole:.*Yes" <<<"$info" || {
  echo "refusing: $DISK is not a whole disk"; exit 1; }
if grep -q "Device Location:.*Internal" <<<"$info"; then
  echo "refusing: $DISK is an internal disk"; exit 1
fi

bytes="$(awk -F'[()]' '/Disk Size:/{print $2}' <<<"$info" | awk '{print $1}')"
imgsz="$(stat -f%z "$IMG")"
if [ -z "${bytes:-}" ] || [ "$bytes" -lt "$imgsz" ]; then
  echo "refusing: $DISK holds ${bytes:-?} bytes, image needs $imgsz"; exit 1
fi

name="$(awk -F': *' '/Device \/ Media Name:/{print $2}' <<<"$info")"
echo "target : $DISK ($name, $bytes bytes)"
echo "image  : $IMG ($imgsz bytes)"
echo "sha256 : $(shasum -a 256 "$IMG" | awk '{print $1}')"
echo "ALL DATA ON $DISK WILL BE DESTROYED"

diskutil unmountDisk "/dev/$DISK"
dd if="$IMG" of="/dev/r$DISK" bs=1m
sync
diskutil eject "/dev/$DISK"
echo "write complete; reinsert the stick to verify, or move it to the TV"
