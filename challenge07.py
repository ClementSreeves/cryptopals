import aes
import utils
import strcon

key = b'YELLOW SUBMARINE'

text = ''.join(utils.import_file("Inputs/7.txt", split=True)) 
text = strcon.base64ToBytes(text)
print(aes.decryptAES_ECB(text, key).decode())
