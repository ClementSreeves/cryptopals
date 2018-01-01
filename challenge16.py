import block
import xor

prefix = b"comment1=cooking%20MCs;userdata="
suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
encryptor, decryptor = block.create_encryptor_and_decryptor(mode='CBC',
                                                            prefix=prefix,
                                                            suffix=suffix)

def encryption_oracle(user_input):
    user_input = user_input.replace(b'=', b'').replace(b';', b'')
    return encryptor(user_input)

def detect_admin(ciphertext):
    return b';admin=true;' in decryptor(ciphertext)

assert(detect_admin(encryptor(b";admin=true")))
assert(not detect_admin(encryption_oracle(b";admin=true")))

block_size = block.calculate_block_size(encryption_oracle)
print("Block size: {}".format(block_size))
block.ECB_CBC_detection(encryption_oracle, block_size=block_size)

#Strategy: 1) Find the input length so that the final block is all padding
#          2) Encrypt with that input length
#          3) Replace the penultimate block with evil_block = 
#             xor(penultimate_block, padding_block, admin_block)
#          4) Decrypting the final block gives
#             xor(penultimate_block, padding_block). So when xor'ed with
#             evil_block, results in admin_block.

#Step 1
def calculate_filler_length(encryptor):
    """Finds the length of input such that the last block is all padding"""
    filler = bytes()
    basic_length = current_length = len(encryptor(filler))
    while basic_length == current_length:
        filler += b'A'
        current_length = len(encryptor(filler))
    return len(filler) 

filler_length = calculate_filler_length(encryption_oracle)

#Step 2
ciphertext = encryption_oracle(b'A' * filler_length)

#Step 3
ciphertext_blocks = block.blockSplit(ciphertext, block_size)
padding_block = bytes(block_size * [block_size])
admin_string = b";admin=true;"
admin_block = admin_string + (b'A' * (block_size - len(admin_string)))
evil_block = xor.xorBytes(xor.xorBytes(ciphertext_blocks[-2], padding_block),
                          admin_block)
modified_ciphertext = b''.join(ciphertext_blocks[:-2] + 
                               [evil_block] +
                               [ciphertext_blocks[-1]])

#Step 4
if detect_admin(modified_ciphertext):
    print("You are now the admin. Muahahahaha")
print(decryptor(modified_ciphertext))
