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
    blockSize = len(key)
    plaintextBlocks = blockSplit(plaintext, blockSize)
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
    blockSize = len(key)
    cipherTextBlocks = blockSplit(ciphertext, blockSize)
    numBlocks = len(cipherTextBlocks)
    plainText = bytes()
    prevBlocks = [IV] + cipherTextBlocks[:-1] #to uncombine 
    for currentBlock, prevBlock in zip(reversed(cipherTextBlocks), 
                                       reversed(prevBlocks)):
        decryptedBlock = decryptAES_ECB(currentBlock, key)
        plainText = xor.xorBytes(decryptedBlock, prevBlock) + plainText
    return plainText

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

class PaddingError(Exception):
    pass

def remove_pkcs_padding(b, block_size=16):
    valid_length = len(b) % block_size == 0
    valid_padding = all([x == b[-1] for x in b[-b[-1]:]])
    if valid_length and valid_padding:
        return b[:-b[-1]]
    else:
        raise PaddingError("String has incorrect padding")

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

def generateRandomBytes(length):
    """Generates random bytes of a given length"""
    return bytes([random.randrange(256) for _ in range(length)])

def containsDuplicates(text, blockSize):
    """Detects whether duplicate blocks are present in the text"""
    blocks = blockSplit(text, blockSize) 
    for x, y in itertools.combinations(blocks, 2):
        if x == y:
            return True
    return False

def findDuplicateBlock(text, blockSize):
    """Finds the value of duplicate blocks in the text"""
    blocks = blockSplit(text, blockSize) 
    for x, y in itertools.combinations(blocks, 2):
        if x == y:
            return x
    return None

def encryption_oracle(plaintext, blockSize=16):
    """Encrypts under ECB or CBC randomly"""
    prefix = generateRandomBytes(random.randint(5, 10))
    suffix = generateRandomBytes(random.randint(5, 10))
    padded = pkcsPadding(prefix + plaintext + suffix, blockSize)

    key = generateRandomBytes(blockSize)
    if random.choice([0, 1]):
        print("ECB used")
        return encryptAES_ECB(padded, key)
    else:
        print("CBC used")
        IV = generateRandomBytes(blockSize)
        return encryptAES_CBC(padded, key, IV)

def create_ECB_encryptor(blockSize=16, random_prefix=False):
    key = generateRandomBytes(blockSize)
    if random_prefix:
         prefix = generateRandomBytes(random.randint(1, 100))
    else:
        prefix = b''
    def ECB_encryption_oracle(my_input, unknown_string):
        padded = pkcsPadding(prefix + my_input + unknown_string, blockSize)
        return encryptAES_ECB(padded, key)
    return ECB_encryption_oracle

def ECB_CBC_detection(encryptor, *args, blockSize=16):
    """Detects whether the encrytor function is using ECB or CBC"""
    if containsDuplicates(encryptor(b'a' * blockSize * 10, *args),
                          blockSize=blockSize):
        print("Detected ECB")
    else:
        print("Detected CBC")

def calculate_block_size(encryptor, *args):
    """Calculates block size of an encryptor.
    
    The encryptor should take an arbitrary input as the first argument, and
    other arguments can be supplied."""
    diffs = []
    for _ in range(20):
        filler = bytes()
        basic_length = current_length = len(encryptor(filler, *args))
        while basic_length == current_length:
            filler += b'A'
            current_length = len(encryptor(filler, *args))
        diffs.append(abs(current_length - basic_length))
    return min(diffs)

def bytewise_ECB_decrypt(encryptor, *args, blockSize=16):
    """Given an oracle that encrypts (user_input || unknown_string) under
    ECB, find unknown_string."""
    string_length = len(encryptor(bytes(), *args)) 
    plaintext = bytes()
    for i in range(string_length):
        block_number, position = divmod(i, blockSize)
        filler = b'A' * (blockSize - position - 1)
        if i >= blockSize - 1:
            byte_short = plaintext[-(blockSize - 1):]
        else:
            byte_short = filler + plaintext
        possible_blocks = [byte_short + bytes([b]) for b in range(256)]
        last_byte = {encryptor(bl, *args)[:blockSize]:
                     bytes([bl[-1]]) for bl in possible_blocks}
        start = block_number * blockSize
        end = start + blockSize
        try:
            plaintext += last_byte[encryptor(filler, *args)[start:end]]
        except KeyError:
            break
    return plaintext

def key_value_parser(encoding):
    """Given a key/value encoding, produces the corresponding dict"""
    items = [item.split('=') for item in encoding.decode().split('&')]
    return {k: v for k, v in items}

def profile_for(email_address):
    profile_for.counter += 1
    email_address = email_address.replace('&', '').replace('=', '')
    profile = {'email': email_address, 
               'uid': str(profile_for.counter),
               'role': 'user'}
    encoded = '&'.join(['='.join(item) for item in profile.items()])
    return encoded.encode(encoding='ascii')
profile_for.counter = 0
