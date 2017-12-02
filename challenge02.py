#!/usr/bin/env python3

import strcon
import xor

b1 = strcon.hexToBytes("1c0111001f010100061a024b53535009181c")
b2 = strcon.hexToBytes("686974207468652062756c6c277320657965")

print(strcon.bytesToHex(xor.xorBytes2(b1, b2)))
