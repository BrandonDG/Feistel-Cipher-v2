#!/usr/bin/python3.5

# Name:           Brandom Gillespie
# Student Number: A00966847
# Class:          COMP7402
# Assignment:     A5
# Purpose:        Encrypt and decrypt plaintext in the Feistel Cipher method.
#                 Plaintext is to be given in an binary string of even length,
#                 The program also requires an amount of rounds for the cipher,
#                 as well as a key.
import sys
import os

# Cipher function that is used before xor.
def cipher_function(i, k, r):
    return (((2 * r * k)**i) % 15)

def feistel_cipher(pt, k, r):
    format_string = "{:08b}"
    pt_b = format_string.format(pt)

    leftside, rightside = int(pt_b[:int(len(pt_b) / 2)], 2), int(pt_b[int(len(pt_b) / 2):], 2)

    for i in range(len(r)):
        xor_value = cipher_function(rightside, k, r[i])
        left_xor = xor_value ^ leftside
        leftside = rightside
        rightside = left_xor

    format_string = "{:04b}"
    result = format_string.format(rightside)
    result += format_string.format(leftside)
    return int(result, 2)

def cbc_e(pt, k, r, iv, cb):
    result_array = []
    format_string = "{:08b}"
    iv_val = ord(iv)

    for c in pt:
        print("Pre Encrypt: " + format_string.format(ord(c)))
        new_c = feistel_cipher(ord(c) ^ iv_val, int(k) ^ iv_val, r)
        result_array.append(chr(new_c))
        iv_val = new_c
        print("Post Encrypt: " + format_string.format(new_c))
        print(chr(new_c))
        cb.write(format_string.format(new_c) + " ")

    return result_array

def cbc_d(pt, k, r, iv, pb):
    result_array = []
    format_string = "{:08b}"
    iv_val = ord(iv)

    for c in pt:
        print("Pre Encrypt: " + format_string.format(ord(c)))
        new_c = feistel_cipher(ord(c), int(k) ^ iv_val, r)
        new_c = new_c ^ iv_val
        result_array.append(chr(new_c))
        iv_val = ord(c)
        print("Post Encrypt: " + format_string.format(new_c))
        print(chr(new_c))
        pb.write(format_string.format(new_c) + " ")

    return result_array


# Main
def main():
    plaintext = ""
    round_inputs = []
    # Get input type
    #while (True):
    #    where_is_plain = input("Is the plaintext given via stdin or file? ")
    #    if where_is_plain == "file":
    #        print("File selected")
    #        plain = input("File name please: ")
    #        plaintext += open(plain, 'rU').read()
    #        plaintext = plaintext.strip('\n')
    #        break
    #    elif where_is_plain == "stdin":
    #        print("stdin selected")
    #        plain = input("Plaintext please: ")
    #        plaintext = plain
    #        break
    #    else:
    #        print("Need to select a valid option ('file' or 'stdin')")

    # Even length check
    #if (len(plaintext) % 2) != 0:
    #    print("Please give plaintext of even length")
    #    sys.exit(0)

    plain = input("Plaintext please: ")
    plaintext = plain

    # Get key and rounds
    key = input("Key please: ")
    rounds = input("Amount of rounds please: ")

    # Show user supplied values
    print("")
    print("Plaintext: " + plaintext)
    print("Key: " + key)
    print("Amount of rounds: " + rounds)
    print("")

    # Create function for rounds
    for i in range(int(rounds)):
        round_inputs.append(i + 1)

    cipher_binary = open("binary_ciphertext", "w")
    plain_binary = open("binary_plaintext", "w")
    iv = os.urandom(1)

    encrypt_result = cbc_e(plaintext, key, round_inputs, iv, cipher_binary)
    print("Ciphertext: ")
    print(encrypt_result)

    print("")

    round_inputs.reverse()
    decrypt_result = cbc_d(encrypt_result, key, round_inputs, iv, plain_binary)
    print("Plaintext: ")
    print(decrypt_result)

    outputfile = open("ciphertext", "wb")
    outputfile.write(bytes("".join(encrypt_result), "utf-8"))
    outputfile.close()

    cipher_binary.close()
    plain_binary.close()

    print("")
    print("Plaintext Binary: ")
    os.system("cat binary_plaintext")
    print("")
    print("Ciphertext Binary: ")
    os.system("cat binary_ciphertext")
    print("")


# Main
if __name__ == "__main__":
    main()
