#!/bin/sh
#
# DON'T EDIT THIS!
#
# CodeCrafters uses this file to test your code. Don't make any changes here!
#
# DON'T EDIT THIS!
set -e
tmpFile=$(mktemp)
gcc -lcurl app/*.c -o $tmpFile -lz
exec "$tmpFile" "$@"
