import base64

def hexToBytes(s):
  return base64.b16decode(s, casefold=True)

def base64ToBytes(s):
  return base64.b64decode(s)

def bytesToBase64(b):
  return base64.b64encode(b)
  
def bytesToHex(b):
  return base64.b16encode(b).lower()
  
def hexToBase64(s):
  return bytesToBase64(hexToBytes(s))
