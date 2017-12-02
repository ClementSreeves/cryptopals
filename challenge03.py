#!/usr/bin/env python3

import strcon
import xor

b = strcon.hexToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373"
                      "e783a393b3736")
plaintext, score, char = xor.singleByteDecrypt(b)

print("Plaintext: {plaintext}\nChar was: {char}".format(plaintext=plaintext,
                                                        char=char))
