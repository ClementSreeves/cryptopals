from Crypto.Cipher import AES
import xor 
import random
import itertools

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

def encryptAES_CBC(plaintext, key, IV):
    """Encrypt a plaintext under AES CBC mode."""
    block_size = len(key)
    plaintextBlocks = blockSplit(plaintext, block_size)
    prevBlock = IV
    ciphertext = bytes()
    for block in plaintextBlocks:
        block = xor.xorBytes(block, prevBlock)
        encryptedBlock = encryptAES_ECB(block, key)
        ciphertext += encryptedBlock
        prevBlock = encryptedBlock
    return ciphertext

def decryptAES_CBC(ciphertext, key, IV): 
    """Decrypt a ciphertext encrypted under AES CBC mode"""
    block_size = len(key)
    cipherTextBlocks = blockSplit(ciphertext, block_size)
    numBlocks = len(cipherTextBlocks)
    plainText = bytes()
    prevBlocks = [IV] + cipherTextBlocks[:-1] #to uncombine 
    for currentBlock, prevBlock in zip(reversed(cipherTextBlocks), 
                                       reversed(prevBlocks)):
        decryptedBlock = decryptAES_ECB(currentBlock, key)
        plainText = xor.xorBytes(decryptedBlock, prevBlock) + plainText
    return plainText

def pkcsPadding(byteArray, block_size):
    """Pads a bytearray using PKCS#7 padding.
  
    Adds padding to a bytearray so that its length is a multiple of the block
    size. The value of the byte that is added is equal to the number of bytes 
    that need to be added. If the length of the bytearray is already a multiple
    of the block size, a whole block is added.
  
    Args:
        byteArray: A bytearray of arbitrary size to be padded
        block_size: An integer representing the block size
  
    Returns:
        The padded bytearray
    """
    paddingLength = block_size - (len(byteArray) % block_size)
    return byteArray + bytearray(paddingLength * [paddingLength])

class PaddingError(Exception):
    pass

def remove_pkcs_padding(b, block_size=16):
    valid_length = len(b) % block_size == 0
    valid_padding = all([x == b[-1] for x in b[-b[-1]:]])
    if valid_length and valid_padding:
        return b[:-b[-1]]
    else:
        raise PaddingError("String has incorrect padding")

def blockSplit(obj, block_size):
    """Splits an object into blocks of a given size.
    
    The resulting blocks are returned in a list. block_size must divide
    len(obj). 

    Args:
        obj: An indexable object to be split
        block_size: An integer size of blocks desired

    Raises:
        ValueError: If block_size does not divide len(obj)

    Returns:
        A list of the resulting blocks
    """
    obj_length = len(obj)
    if obj_length % block_size:
        raise ValueError("block_size must divide the length of the object")
    else:
        return [obj[i:i+block_size] for i in range(0, obj_length, block_size)]

def generateRandomBytes(length):
    """Generates random bytes of a given length"""
    return bytes([random.randrange(256) for _ in range(length)])

def containsDuplicates(text, block_size):
    """Detects whether duplicate blocks are present in the text"""
    blocks = blockSplit(text, block_size) 
    for x, y in itertools.combinations(blocks, 2):
        if x == y:
            return True
    return False

def findDuplicateBlock(text, block_size):
    """Finds the value of duplicate blocks in the text"""
    blocks = blockSplit(text, block_size) 
    for x, y in itertools.combinations(blocks, 2):
        if x == y:
            return x
    return None

def encryption_oracle(plaintext, block_size=16):
    """Encrypts under ECB or CBC randomly"""
    prefix = generateRandomBytes(random.randint(5, 10))
    suffix = generateRandomBytes(random.randint(5, 10))
    padded = pkcsPadding(prefix + plaintext + suffix, block_size)

    key = generateRandomBytes(block_size)
    if random.choice([0, 1]):
        print("ECB used")
        return encryptAES_ECB(padded, key)
    else:
        print("CBC used")
        IV = generateRandomBytes(block_size)
        return encryptAES_CBC(padded, key, IV)

class ModeError(Exception):
    pass

def create_encryptor(mode='ECB', suffix=b'', prefix=b'', block_size=16):
    if mode not in ('ECB', 'CBC'): 
        raise ModeError("Unknown Mode: {}".format(mode))
    key = generateRandomBytes(block_size)
    if mode == 'CBC':
        IV = generateRandomBytes(block_size)
    def encryption_oracle(user_input):
        padded = pkcsPadding(prefix + user_input + suffix, block_size)
        if mode == 'ECB':
            return encryptAES_ECB(padded, key)
        else:
            return encryptAES_CBC(padded, key, IV)
    return encryption_oracle

def create_encryptor_and_decryptor(mode='ECB', suffix=b'', prefix=b'',
                                   block_size=16):
    if mode not in ('ECB', 'CBC'): 
        raise ModeError("Unknown Mode: {}".format(mode))
    key = generateRandomBytes(block_size)
    if mode == 'CBC':
        IV = generateRandomBytes(block_size)
    def encryption_oracle(user_input):
        padded = pkcsPadding(prefix + user_input + suffix, block_size)
        if mode == 'ECB':
            return encryptAES_ECB(padded, key)
        else:
            return encryptAES_CBC(padded, key, IV)
    def decryption_oracle(ciphertext):
        if mode == 'ECB':
            return decryptAES_ECB(ciphertext, key)
        else:
            return decryptAES_CBC(ciphertext, key, IV)
    return (encryption_oracle, decryption_oracle) 

def ECB_CBC_detection(encryptor, block_size=16):
    """Detects whether the encrytor function is using ECB or CBC"""
    if containsDuplicates(encryptor(b'a' * block_size * 10),
                          block_size=block_size):
        print("Detected ECB")
    else:
        print("Detected CBC")

def calculate_block_size(encryptor):
    """Calculates block size of an encryptor."""
    filler = bytes()
    basic_length = current_length = len(encryptor(filler))
    while basic_length == current_length:
        filler += b'A'
        current_length = len(encryptor(filler))
    return current_length - basic_length
