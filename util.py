import collections
import string

'''collection of useful dictionaries, constantts, and functions for ciphers.'''

alphabet = string.ascii_uppercase
nums = {x:y for x,y in zip(alphabet,range(0,26))}
letters = {y:x for x,y in zip(alphabet,range(0,26))}
frequencies = collections.OrderedDict({'E':12.51,'T':9.25,'A':8.04,'O':7.60,'I':7.26,'N':7.09,'S':6.54,'R':6.12,'H':5.49,'L':4.14,'D':3.99,'C':3.06,'U':2.71,'M':2.53,'F':2.30,'P':2.00,'G':1.96,'W':1.92,'Y':1.73,'B':1.54,'V':0.99,'K':0.67,'X':0.19,'J':0.16,'Q':0.11,'Z':0.09})

def modInverse(a, m) : 
    a = a % m
    for x in range(1, m):
        if ((a * x) % m == 1):
            return x 
    return 1

def get_cipher_frequencies(ciphertext):
    cipher_frequencies = dict.fromkeys(alphabet,0)
    cipher_len = len(ciphertext)
    for letter in ciphertext:
        cipher_frequencies[letter]+=1.0/cipher_len
    return collections.OrderedDict(cipher_frequencies)


    