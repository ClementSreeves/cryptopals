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

def gen_initial_array(seed, n=624, w=32, f=1812433253):
    mask = (2 ** w) - 1
    array = [seed]
    x = seed
    for i in range(1, n):
        x = (f * (x ^ (x >> (w - 2))) + i) & mask
        array.append(x)
    return array

def mt19937(seed):
    w, n, m, r = (32, 624, 397, 31) 
    a = int('9908B0DF', base=16)
    b, c = (int('9D2C5680', base=16), int('EFC60000', base=16))
    s, t = (7, 15)
    u, d, l = (11, int('FFFFFFFF', base=16), 18)
    f = 1812433253    
    array = gen_initial_array(seed) 
    l_mask = (2 ** r) - 1
    u_mask = ((2 ** w) - 1) ^ l_mask
    def rand():
        while True:
            concat = (array[0] & u_mask) | (array[1] & l_mask)
            twist = (concat >> 1) ^ a if concat % 2 else concat >> 1
            x = array[m] ^ twist
            y = x ^ ((x >> u) & d)
            y = y ^ ((y << s) & b)
            y = y ^ ((y << t) & c)
            yield y ^ (y >> l)
            array.append(x)
            array.pop(0)
    return rand()
