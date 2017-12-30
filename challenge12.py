import block
import strcon

unknown_string = strcon.base64ToBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWc"
                                      "tdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdw"
                                      "pUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZ"
                                      "yBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/"
                                      "IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
encryption_oracle = block.create_ECB_encryptor()

blockSize = block.calculate_block_size(encryption_oracle, unknown_string)
print("Block Size: {}".format(blockSize))

block.ECB_CBC_detection(encryption_oracle, unknown_string, blockSize=blockSize)

def find_suffix_length(encryptor, *args, blockSize=16):
    test_input = b''
    basic_length = len(encryptor(test_input, *args))
    for i in range(blockSize):
        test_input += b'A'
        length = len(encryptor(test_input, *args))
        if length > basic_length:
            return length - blockSize - len(test_input)

def bytewise_ECB_decrypt(encryptor, *args, blockSize=16):
    """Given an oracle that encrypts (user_input || unknown_string) under
    ECB, find unknown_string."""
    string_length = find_suffix_length(encryptor, *args) 
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
        plaintext += last_byte[encryptor(filler, *args)[start:end]]
    return plaintext

print(bytewise_ECB_decrypt(encryption_oracle,
                           unknown_string,
                           blockSize=blockSize).decode())

