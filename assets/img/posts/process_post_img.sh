#!/bin/bash

exiftool -all= -overwrite_original .
for i in $1; do sum=$(sha256sum $1); echo -- "$i" "${sum%% *}.${i##*.}"; mv "$i" "${sum%% *}.${i##*.}"; done
