import string
import strcon
import itertools

class InputError(Exception):
    pass

def singleByteXor(b, char):
    char_bytes = bytes([char] * len(b))
    return xorBytes(b, char_bytes)
        
def repeatingKeyXor(b, key):
    d, r = divmod(len(b), len(key))
    return xorBytes(b, bytes(key * d + key[:r]))

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

def bitCount(i):
    count = 0
    while(i):
        i &= (i-1)
        count += 1
    return count

def hammingDistance(b1, b2):
    b3 = xorBytes(b1, b2)
    return sum([bitCount(i) for i in b3])

def keySizeScore(b, keysize, sampleblocks=4):
    """Finds the average hamming distance between the first blocks, normalised
       by keysize"""
    blocks = [b[i:i+keysize]
              for i in range(0, sampleblocks * keysize, keysize)]
    scores = [hammingDistance(b1, b2)
              for b1, b2 in itertools.combinations(blocks, 2)]
    return (sum(scores) / len(scores)) / keysize 

def decryptRepeatingKeyXor(ciphertext):
    """Given a ciphertext that has been encrypted using repeating key xor,
       find the plaintext and key"""
    #find the best keysize based on hamming distance
    scores = [(i, keySizeScore(ciphertext, i)) for i in range(2, 41)]
    keyLength = sorted(scores, key=lambda x: x[1])[0][0]
    blocks = [ciphertext[i::keyLength] for i in range(keyLength)]

    #decrypt each block
    keyGuess = ''
    plaintextblocks = []
    for block in blocks:
        (result, score, key) = singleByteDecrypt(block)
        keyGuess += key
        plaintextblocks.append(result)

    #put the decrypted blocks back together
    space = 30
    plaintext = itertools.zip_longest(*plaintextblocks, fillvalue=space)
    return (b''.join([bytes(i) for i in plaintext]), keyGuess)
