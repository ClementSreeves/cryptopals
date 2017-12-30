import block

test_strings = [b"ICE ICE BABY\x04\x04\x04\x04",
                b"ICE ICE BABY\x05\x05\x05\x05",
                b"ICE ICE BABY\x01\x02\x03\x04"]

for string in test_strings:
    try:
        print("Padded string: {}".format(string))
        print("Becomes: {}".format(block.remove_pkcs_padding(string)))
    except block.PaddingError:
        print("Contains Padding Error")
    finally: print("\n")

