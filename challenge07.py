import utils
import strcon
import block

key = b'YELLOW SUBMARINE'

text = ''.join(utils.import_file("Inputs/7.txt", split=True)) 
text = strcon.base64ToBytes(text)
print(block.decryptAES_ECB(text, key).decode())
