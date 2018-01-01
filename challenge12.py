import block
import strcon

unknown_string = strcon.base64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWc"
                                      "tdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdw"
                                      "pUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZ"
                                      "yBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/"
                                      "IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
encryption_oracle = block.create_encryptor(mode='ECB', suffix=unknown_string)

block_size = block.calculate_block_size(encryption_oracle)
print("Block Size: {}".format(block_size))

block.ECB_CBC_detection(encryption_oracle, block_size=block_size)

def find_suffix_length(encryptor, block_size=16):
    test_input = b''
    basic_length = len(encryptor(test_input))
    for i in range(block_size):
        test_input += b'A'
        length = len(encryptor(test_input))
        if length > basic_length:
            return length - block_size - len(test_input)

def bytewise_ECB_decrypt(encryptor, block_size=16):
    """Given an oracle that encrypts (user_input || unknown_string) under
    ECB, find unknown_string."""
    string_length = find_suffix_length(encryptor) 
    plaintext = bytes()
    for i in range(string_length):
        block_number, position = divmod(i, block_size)
        filler = b'A' * (block_size - position - 1)
        if i >= block_size - 1:
            byte_short = plaintext[-(block_size - 1):]
        else:
            byte_short = filler + plaintext
        possible_blocks = [byte_short + bytes([b]) for b in range(256)]
        last_byte = {encryptor(bl)[:block_size]:
                     bytes([bl[-1]]) for bl in possible_blocks}
        start = block_number * block_size
        end = start + block_size
        plaintext += last_byte[encryptor(filler)[start:end]]
    return plaintext

print(bytewise_ECB_decrypt(encryption_oracle,
                           block_size=block_size).decode())

