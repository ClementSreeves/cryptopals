import block
import xor

def increment_block_count(b):
    b = bytearray(b)
    for i, byte in enumerate(b):
        if byte == 255:
            b[i] = 0
        else:
            b[i] += 1
            return bytes(b)
    return bytes(b) 
        
def CTR_mode(stream, key, nonce, block_size=16):
    stream_length = len(stream)
    stream = block.pkcsPadding(stream, block_size)
    stream_blocks = block.blockSplit(stream, block_size)
    output = bytes()
    block_count = bytes([0] * (block_size // 2))
    for bl in stream_blocks:
        keystream = block.encryptAES_ECB(nonce + block_count, key)
        output += xor.xorBytes(bl, keystream)
        block_count = increment_block_count(block_count)
    return output[:stream_length]

