import block
import strcon
import random

strings = [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
           b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlI"
           b"HB1bXBpbic=",
           b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZ"
           b"w==",
           b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
           b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
           b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
           b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
           b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
           b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
           b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

block_size = 16
key = block.generateRandomBytes(block_size)
IV = block.generateRandomBytes(block_size)
secret_string = strcon.base64ToBytes(random.choice(strings))

def encryption_oracle():
    padded = block.pkcsPadding(secret_string, block_size)
    return (block.encryptAES_CBC(padded, key, IV), IV)

def has_valid_padding(ciphertext):
    decrypted = block.decryptAES_CBC(ciphertext, key, IV)
    try:
        block.remove_pkcs_padding(decrypted, block_size)
        return True
    except block.PaddingError:
        return False

assert(has_valid_padding(encryption_oracle()[0]))

#Strategy: 1) Compile (prev_block || block) strings from the ciphertext and IV
#          2) For each string repeat steps 3-6:
#          3) Use bitflipping on prev_block to edit the final byte of block 
#          4) Eventually the padding oracle will return True
#          5) Perform xor(\x01, edit) to get the plaintext byte
#          6) Edit the final byte to \x02, and cycle through edits for the
#             penultimate byte until we get valid padding etc.

#Step 1
ciphertext, IV = encryption_oracle()
blocks = [IV] + block.blockSplit(ciphertext, block_size)
consec_blocks_list = [blocks[i:i+2] for i in range(len(blocks) - 1)]

# Step 2
def decrypt_block(consec_blocks, reverse_search=False):
    """Given a list [prev_block, block], decrypts block"""
    prev_block, block = consec_blocks 
    prev_block_edit = bytearray(prev_block)
    plaintext = bytes()
    for i in range(1, len(block) + 1):
        start_val = prev_block_edit[-i]
        search_range = range(255, -1, -1) if reverse_search else range(256)
        for b in search_range:
            prev_block_edit[-i] = b
            if has_valid_padding(bytes(prev_block_edit + block)):
                edit = start_val ^ b
                plaintext = bytes([edit ^ i]) + plaintext
                break
        #In case correct padding is recreated in a final block
        if len(plaintext) != i:
            return decrypt_block(consec_blocks, reverse_search=True)
        # set last i bytes so that block will have appropriate padding
        increment_byte = i ^ (i + 1)
        prev_block_edit[-i:] = [x ^ increment_byte
                                for x in prev_block_edit[-i:]] 
    return plaintext

plaintext = b''.join([decrypt_block(bs) for bs in consec_blocks_list])
print(block.remove_pkcs_padding(plaintext, block_size).decode())
