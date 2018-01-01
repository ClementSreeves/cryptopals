import block
import strcon

unknown_string = strcon.base64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWc"
                                      "tdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdw"
                                      "pUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZ"
                                      "yBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/"
                                      "IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
block_size = 16
random_prefix = block.generateRandomBytes(block_size)
encryption_oracle = block.create_encryptor(mode='ECB', 
                                           suffix=unknown_string,
                                           prefix=random_prefix)

block.ECB_CBC_detection(encryption_oracle)

def find_prefix_length(encryptor, block_size=16):
    test_input = b'A' * block_size * 2
    for i in range(block_size):
        encrypted_block = encryptor(test_input)
        duplicate_block = block.findDuplicateBlock(encrypted_block, block_size)
        if duplicate_block: 
            duplicate_index = block.blockSplit(
                encrypted_block, block_size).index(duplicate_block)
            prefix_length = (duplicate_index * block_size) - i
        test_input = b'B' + test_input
    return prefix_length
    
def find_suffix_length(encryptor, prefix_length, block_size=16):
    test_input = b''
    basic_length = len(encryptor(test_input))
    for i in range(block_size):
        test_input += b'A'
        length = len(encryptor(test_input))
        if length > basic_length:
            return length - block_size - len(test_input) - prefix_length

def bytewise_ECB_decrypt(encryptor, block_size=16):
    """Given an oracle that encrypts (random-prefix || user_input ||
    unknown_string) under ECB, find unknown_string."""
    prefix_length = find_prefix_length(encryptor)
    #craft a prefix to make sure we start at a new block
    input_prefix = b'B' * (block_size - (prefix_length % block_size))
    string_length = find_suffix_length(encryptor, prefix_length)
    plaintext = bytes()
    for i in range(string_length):
        block_number, position = divmod(i + prefix_length + len(input_prefix),
                                        block_size)
        filler = b'A' * (block_size - position - 1)
        if i >= block_size - 1:
            byte_short = plaintext[-(block_size - 1):]
        else:
            byte_short = filler + plaintext
        possible_blocks = [byte_short + bytes([b]) for b in range(256)]
        find_encrypted = lambda x: block.findDuplicateBlock(
            encryptor(input_prefix + (2 * x)), block_size)
        last_byte = {find_encrypted(bl): bytes([bl[-1]])
                     for bl in possible_blocks}
        start = block_number * block_size
        end = start + block_size
        plaintext += last_byte[encryptor(input_prefix + filler)[start:end]]
    return plaintext

print(bytewise_ECB_decrypt(encryption_oracle).decode())

