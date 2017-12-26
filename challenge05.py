import strcon
import xor

plaintext = bytes("Burning 'em, if you ain't quick and nimble\n"
                  "I go crazy when I hear a cymbal", 
                  encoding='ascii')
key = b"ICE"

print(strcon.bytesToHex(xor.repeatingKeyXor(plaintext, key)))
