import stream
import utils
import strcon
import block
import xor

key_size = 16
nonce_size = key_size // 2
key = block.generateRandomBytes(key_size)
nonce = bytes([0] * nonce_size)

base64texts = utils.import_file("Inputs/19.txt", split=True)
plaintexts = map(strcon.base64ToBytes, base64texts)
ciphertexts = [stream.CTR_mode(p, key, nonce) for p in plaintexts]

min_len = len(min(ciphertexts, key=len))
transposed_result = []
for i in range(min_len):
    letters = bytes([c[i] for c in ciphertexts])
    transposed_result.append(xor.singleByteDecrypt(letters)[0].decode())
result = [''.join(s) for s in zip(*transposed_result)]
for r in result:
    print(r)
