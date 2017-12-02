from Crypto.Cipher import AES

def decryptAES_ECB(ciphertext, key):
    """Decrypt a ciphertext encrypted under AES ECB mode.
    
    Args: 
        ciphertext: Bytes object ciphertext to be decrypted
        key: Bytes object encryption key
        
    Returns: Bytes object plaintext
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext) 

def encryptAES_ECB(plaintext, key):
    """Encrypt a plaintext under AES ECB mode.
    
    Args: 
        plaintext: Bytes object plaintext to be encrypted
        key: Bytes object encryption key
        
    Returns: Bytes object ciphertext 
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext) 

def pkcsPadding(byteArray, blockSize):
    """Pads a bytearray using PKCS#7 padding.
  
    Adds padding to a bytearray so that its length is a multiple of the block
    size. The value of the byte that is added is equal to the number of bytes 
    that need to be added. If the length of the bytearray is already a multiple
    of the block size, a whole block is added.
  
    Args:
        byteArray: A bytearray of arbitrary size to be padded
        blockSize: An integer representing the block size
  
    Returns:
        The padded bytearray
    """
    paddingLength = blockSize - (len(byteArray) % blockSize)
    return byteArray + bytearray(paddingLength * [paddingLength])

def blockSplit(obj, blockSize):
    """Splits an object into blocks of a given size.
    
    The resulting blocks are returned in a list. blockSize must divide
    len(obj). 

    Args:
        obj: An indexable object to be split
        blockSize: An integer size of blocks desired

    Raises:
        ValueError: If blockSize does not divide len(obj)

    Returns:
        A list of the resulting blocks
    """
    obj_length = len(obj)
    if obj_length % blockSize:
        raise ValueError("blockSize must divide the length of the object")
    else:
        return [obj[i:i+blockSize] for i in range(0, obj_length, blockSize)]
