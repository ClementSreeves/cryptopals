import xor
import strcon
import aes
import itertools

#key = b'YELLOW SUBMARINE'
#print (len(key))
#with open('aes-ecb.txt','r') as f:
#  text = ''.join(([l.rstrip() for l in f]))
#  text = strcon.base64ToBytes(text)
#  print(aes.decryptAES_ECB(text, key).decode())
#
#with open('vigenere.txt','r') as f:
#  text = ''.join(([l.rstrip() for l in f]))
#  text = strcon.base64ToBytes(text)
#  scores = [(i, xor.keySizeScore(text, i)) for i in range(2, 41)]
#  bestScores = sorted(scores, key=lambda x: x[1])[:3]
#  for score in bestScores:
#    keyLength = score[0]
#    blocks = [text[i::keyLength] for i in range(keyLength)]
##    print('Key length: {keyLength}'.format(keyLength=keyLength))
#    keyGuess = ''
#    for block in blocks:
#      (result, score, key) = xor.singleByteDecrypt(block)
##      print('Secret: {s} Key: {key}'.format(s=result.decode(encoding='ascii', errors='replace'),key=key))
#      keyGuess += chr(key)
#    print('Key Guess: {}'.format(keyGuess))
#    print(xor.encryptRepeatingKeyXor(text.decode(), keyGuess).decode()) 
#  
##text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
#
#key = 'ICE'
#
#print(xor.encryptRepeatingKeyXor(text, key))
#
#with open('hexstrings.txt','r') as f:
#  for line in f:
#    (result, score, key) = xor.singleByteDecrypt(line.replace('\n',''))
#    if score > 200:
#      print('Score: {score} Secret: {s} Key: {key}'.format(score=score, s=result.decode(encoding='ascii', errors='replace'),key=key))
