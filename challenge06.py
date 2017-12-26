import utils
import strcon
import xor

ciphertext = ''.join(utils.import_file("Inputs/6.txt", split=True))
ciphertext = strcon.base64ToBytes(ciphertext)

plaintext, key = xor.decryptRepeatingKeyXor(ciphertext)
print(plaintext.decode())
print("Key was: {}".format(key))
