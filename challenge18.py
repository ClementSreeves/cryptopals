import stream
import strcon

block_size = 16
ciphertext = strcon.base64ToBytes(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXz"
                                  b"hPweyyMTJULu/6/kXX0KSvoOLSFQ==")
key = b"YELLOW SUBMARINE"
nonce = bytes([0] * (block_size // 2))

plaintext = stream.CTR_mode(ciphertext, key, nonce, block_size=block_size)

print(plaintext.decode())
