import block
import xor
import strcon

blockSize = 16
key = bytes("YELLOW SUBMARINE", encoding='ascii')
IV = bytes([0]*blockSize)

with open('10.txt','r') as f:
  ciphertext = ''.join([line.strip() for line in f])

ciphertext = strcon.base64ToBytes(ciphertext)
cipherTextBlocks = [ciphertext[i:i+blockSize] for i in range(
  0, len(ciphertext), blockSize)]

numBlocks = len(cipherTextBlocks)

plainText = bytes()
prevBlocks = [IV] + cipherTextBlocks[:-1] #to uncombine 

for currentBlock, prevBlock in zip(reversed(cipherTextBlocks), 
                                   reversed(prevBlocks)):
  decryptedBlock = block.decryptAES_ECB(currentBlock, key)
  plainText = xor.xorBytes(decryptedBlock, prevBlock) + plainText

print(plainText.decode(encoding='utf-8', errors='ignore'))

#for block in plaintext:
#  combined = xor.xorBytes(block, prevEncryptedBlock)
#  encryptedBlock = block.encryptAES_ECB(combined, key)
#  cipherText += encryptedBlock
#  prevEncrypedBlock = encryptedBlock
  
