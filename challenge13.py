import block

block_size = 16
key = block.generateRandomBytes(block_size)

def key_value_parser(encoding):
    """Given a key/value encoding, produces the corresponding dict"""
    items = [item.split('=') for item in encoding.decode().split('&')]
    return {k: v for k, v in items}

def profile_for(email_address):
    """Given an email address, produces the encoded user profile"""
    if type(email_address) == str:
        email_address = email_address.encode()
    profile_for.counter += 1
    email_address = email_address.replace(b'&', b'').replace(b'=', b'')
    profile = {b'email': email_address, 
               b'uid': bytes(str(profile_for.counter), encoding='utf8'),
               b'role': b'user'}
    return b'&'.join([b'='.join(item) for item in profile.items()])
profile_for.counter = 0

def profile_encryptor(encoded_profile, key):
    return block.encryptAES_ECB(block.pkcsPadding(
        encoded_profile, block_size=16), key)

def profile_decryptor(encrypted_profile, key):
    return key_value_parser(block.remove_pkcs_padding(
        block.decryptAES_ECB(encrypted_profile, key)))

def encrypted_profile(email_address, key=key):
    return profile_encryptor(profile_for(email_address), key)
    
print("Block size: {}".format(block.calculate_block_size(encrypted_profile)))
block.ECB_CBC_detection(encrypted_profile)

#Strategy: 1) Find the encrypted block for "user" + padding_bytes
#          2) Feed input of different lengths until that block is found
#          3) Find the encrypted block for "admin" + padding_bytes
#          4) Replace the user block with the admin block

def find_encrypted(plaintext_block, block_size=16):
    crafted_input = b'A' * (block_size - len("email=")) + (plaintext_block * 2)
    return block.findDuplicateBlock(encrypted_profile(crafted_input),
                                    block_size)
    
#step 1
user_email = block.pkcsPadding(b"user", block_size)
user_block = find_encrypted(user_email)
#step 2
for i in range(block_size):
    email = b'A' * i
    if user_block in block.blockSplit(encrypted_profile(email), block_size):
        attack_length = i
        break
#step 3
admin_email = block.pkcsPadding(b"admin", block_size)
admin_block = find_encrypted(admin_email)
#step 4
attacked_profile = encrypted_profile(b'A' * attack_length)
attacked_profile_blocks = block.blockSplit(attacked_profile, block_size)
modified_profile = b''.join(attacked_profile_blocks[:-1] + [admin_block])
#reveal
print(profile_decryptor(modified_profile, key))
