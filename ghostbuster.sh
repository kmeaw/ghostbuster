#!/bin/bash -eu
runpatch()
{
	FILE="$1"
	POS=$(grep -obUaP "\xf8\xff\x4d\x85\xe4\x48\x8d\x50\x21\x0f\x84\x83\x03\x00\x00" "$FILE" | cut -d: -f1)
	if test -z "$POS"; then
		echo "Haystack is missing, aborting..." >&2
		return
	fi
	printf "\xf8\xff\x4d\x85\xe4\x48\x8d\x50\x29\x0f\x84\x83\x03\x00\x00" | dd of="$FILE" bs=1 seek="$POS" conv=notrunc
	#                                         ^^ +sizeof(*h_alias_ptr)
}

detect()
{
	echo "Checking $1..."
	MD5=$(md5sum - < $1 | cut -d' ' -f1)
	if [ "$MD5" = "f3f632e2aa8ad177f56735fd3700d31f" -o "$MD5" = "bf02a9a38618abbd46cc10bdfec1fbca" -o "$MD5" = "93d06c4400f88574ce791694137c669d" -o "$MD5" = "3e7d0679edfe419d1140bfd60080b951" -o "$MD5" = "1291edd69f0b687d05d72e64b2d4ae45" ]; then
		echo "Vulnerable, patching..."
		runpatch $1
	elif [ "$MD5" = "6e908dd7e69f8617b9158fbaca5b0f71" -o "$MD5" = "a4732590fdd4f9e1c224f79feff7bb2e" -o "$MD5" = "64eb929e69bde789d724ac89ec927b8f" -o "$MD5" = "84bd448a20811e83de94f56cdc0bf4a2" -o "$MD5" = "f49adccf812efdb5aa2ad87a94030a29" ]; then
		echo "Already patched."
	elif [ "$MD5" = "cdd431223b10776be89e4578c76b5946" ]; then
		echo "Non-vulnerable version."
	else
		echo "Unknown version: $MD5."
	fi
}

main()
{
	detect /lib/x86_64-linux-gnu/libc-2.15.so
	DELETED=$(grep 'libc-2.15.so (deleted)' /proc/1/maps -m1 || true)
	if test -n "$DELETED"; then
		echo "You have a deleted (possibly, unpatched) version of libc."
		BDEV=$(echo "$DELETED" | awk '{print $4}')
		SONODE=$(echo "$DELETED" | awk '{print $5}')
		SONAME=$(echo "$DELETED" | awk '{print $6}')
		BFILE="/tmp/dev-$$-$BDEV"
		BMAJ=${BDEV%:*}
		BMIN=${BDEV#*:}
		mknod $BFILE b $((0x$BMAJ)) $((0x$BMIN))
		rm -f /vuln || true
		echo -e "ln <$SONODE> /vuln\nclose -a\nq" | debugfs -w $BFILE
		echo 2 > /proc/sys/vm/drop_caches
		detect /vuln
		rm -f /vuln
	fi
}

if [ -z "${1:-}" ]; then
	main
else
	detect "$1"
fi

