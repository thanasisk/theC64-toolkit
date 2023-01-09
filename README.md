# theC64-toolkit
## A Toolkit for TheC64Maxi and TheC64Mini firmware
Other tools require you to know the key (a lot of searching and/or reversing required)
or are closed source.

## Prerequisites
- GNU make
- gcc
- Golang > 1.17
- libgcrypt development files

## Why a mix of C and Golang?
Golang's `Twofish` implementation does not support `CFB` mode and was producing
invalid results. Unfortunately, after trying a couple of the other languages that I know, the problem remained.
Reversing, I found out that `libgcrypt 1.7.3` was used to encrypt the firmware so I decided to use the same library.

Plus, it was a nice experiment with `cgo` :-)

## LICENSE
GPL v3
