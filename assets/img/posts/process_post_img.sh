#!/bin/bash

exiftool -all= -overwrite_original .
for i in *; do sum=$(echo -n "$i"|md5sum); echo -- "$i" "${sum%% *}.${i##*.}"; mv "$i" "${sum%% *}.${i##*.}"; done
