#!/bin/bash
#
# usage: ./genbrut.sh ../hohha 2 128 500
#

PROGR=$1

NUM_J=$2
NUM_K=$3
NUM_T=$4

K=$(../scripts/genmsg.py "$NUM_K")

KEY="brut-j$NUM_J-k$NUM_K-t$NUM_T-key.txt"
MSG="brut-j$NUM_J-k$NUM_K-t$NUM_T-msg.txt"

rm -f "$KEY" "$MSG"

echo "$K" > "$KEY"

for ((i=0; i<NUM_T; ++i)); do
	S=$(../scripts/gensalt.py)
	echo "$S" >> "$MSG"
	M=$(../scripts/genmsg.py 128)
	echo "$M" >> "$MSG"
	X=$("$PROGR" -e -j "$NUM_J" -k "$K" -S "$S" -m "$M")
	echo "$X" >> "$MSG"
done
