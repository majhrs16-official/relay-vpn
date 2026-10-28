#!/bin/sh
set -eu

./gradlew assembleDebug
mkdir -p dist
cp app/build/outputs/apk/debug/app-debug.apk dist/vpn-debug.apk
printf 'APK: %s\n' "$(pwd)/dist/vpn-debug.apk"
