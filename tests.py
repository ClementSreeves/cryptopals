import unittest

import xor
import strcon
import block

class TestMethods(unittest.TestCase):

  def testHexToBase64(self):
    self.assertEqual(strcon.hexToBase64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'),
                      b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

  def testXORBytes(self):
    b1 = strcon.hexToBytes(b'1c0111001f010100061a024b53535009181c')
    b2 = strcon.hexToBytes(b'686974207468652062756c6c277320657965')
    result = xor.xorBytes(b1,b2)
    self.assertEqual(strcon.bytesToHex(result), b'746865206b696420646f6e277420706c6179') 
    
  def testPkcsPadding(self):
    self.assertEqual(block.pkcsPadding(bytearray("YELLOW SUBMARINE", encoding='ascii'), 20),
      bytearray("YELLOW SUBMARINE\x04\x04\x04\x04", encoding='ascii'))

if __name__ == '__main__':
    unittest.main()
