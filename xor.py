import string
import strcon

class InputError(Exception):
    pass

def singleByteXor(b, char):
    char_bytes = bytes([char] * len(b))
    return xorBytes(b, char_bytes)
        
def repeatingKeyXor(s, key):
    d, r = divmod(len(s), len(key))
    b = bytearray(key * d + key[:r])
    return xorBytes(s, b)

def xorBytes(b1, b2):
    if len(b1) != len(b2):
        raise InputError("bytes must have equal length")        
    return bytes([b1[j] ^ b2[j] for j in range(len(b1))])

def scoreChar(c):
    if (97 <= c <= 122) or c==32:
        return 10
    elif 65 <= c <= 90:
        return 5
    elif (33 <= c <= 64) or (91 <= c <= 96) or (123 <= c <= 126):
        return 2
    else:
        return -10
  
def freqScore(bt):
    return sum([scoreChar(c) for c in bt])

def singleByteDecrypt(b):
    results = []
    for i in range(256):
        result = singleByteXor(b, i)
        score = freqScore(result)
        results.append((result, score, chr(i)))
    return sorted(results, key=lambda x: x[1], reverse=True)[0]

def encryptRepeatingKeyXor(s,key):
    s, key = (s.encode(), key.encode())
    return repeatingKeyXor(s,key)

def bitCount(i):
    count = 0
    while(i):
        i &= (i-1)
        count += 1
    return count

def hammingDistance(b1, b2):
    b3 = xorBytes(b1, b2)
    return sum([bitCount(i) for i in b3])

def keySizeScore(b, keysize):
    d1 = hammingDistance(b[:keysize], b[keysize:2*keysize])
    d2 = hammingDistance(b[2*keysize:3*keysize], b[3*keysize:4*keysize])
    d3 = hammingDistance(b[:keysize], b[3*keysize:4*keysize])
    d4 = hammingDistance(b[:keysize], b[2*keysize:3*keysize])
    d5 = hammingDistance(b[2*keysize:3*keysize], b[keysize:2*keysize])
    d6 = hammingDistance(b[keysize:2*keysize], b[3*keysize:4*keysize])
  
    d = (d1 + d2 + d3 + d4 + d5 + d6) / 6
    return d/keysize
