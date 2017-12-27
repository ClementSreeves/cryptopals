import utils
import block
import strcon

key = b"YELLOW SUBMARINE"
IV = bytes([0] * len(key))

ciphertext = ''.join(utils.import_file('Inputs/10.txt', split=True))
ciphertext = strcon.base64ToBytes(ciphertext)
    
plaintext = block.decryptAES_CBC(ciphertext, key, IV)

print(plaintext.decode())

assert(block.encryptAES_CBC(plaintext, key, IV) == ciphertext)
