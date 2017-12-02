import strcon
import itertools
import block

block_length = 16

with open('aes-ecb-2.txt', 'r') as f:
    texts = [strcon.hexToBytes(line.strip()) for line in f.readlines()]
for text in texts:
    blocks = block.blockSplit(text, block_length) 
    for combo in itertools.combinations(blocks, 2):
        if combo[0] == combo[1]:
            print('Detected duplicate! Text was {0}, block was {1}'.format(
                strcon.bytesToHex(text), strcon.bytesToHex(combo[0])))
