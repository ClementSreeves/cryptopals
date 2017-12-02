#!/usr/bin/env python3

import strcon
import xor
import utils

hex_strings = utils.import_file("Inputs/4.txt", split=True)
byte_strings = [strcon.hexToBytes(s) for s in hex_strings]

for b in byte_strings:
    (result, score, key) = xor.singleByteDecrypt(b)
    if score > 200:
        print('Score: {score}\nPlaintext: {s}\nKey: {key}'.format(score=score,
                                                                  s=result,
                                                                  key=key))
