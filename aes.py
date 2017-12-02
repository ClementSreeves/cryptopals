from Crypto.Cipher import AES

def decryptAES_ECB(ciphertext, key):
  cipher = AES.new(key, AES.MODE_ECB)
  return cipher.decrypt(ciphertext) 
