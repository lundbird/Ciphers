import string
import collections
import csv
import abc
from util import *
import numpy as np
from itertools import cycle

class Cipher(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def encrypt(self,plaintext,*key):
        pass

    @abc.abstractmethod
    def decrypt(self,ciphertext,*key):
        pass
    
    @abc.abstractmethod
    def crack(self,ciphertext,plaintext=None):
        pass

class Shift(Cipher):

    def encrypt(self,plaintext,shift):
        shifted_alphabet = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(alphabet, shifted_alphabet)
        return plaintext.translate(table)
        
    def decrypt(self,ciphertext, shift):
        shifted_alphabet = alphabet[shift:] + alphabet[:shift]
        table = str.maketrans(shifted_alphabet,alphabet)
        return ciphertext.translate(table)

    def crack(self,ciphertext,plaintext=None):
        sums={}
        for shift in range(26):
            shifted_string = self.decrypt(ciphertext,shift)
            cipher_frequencies = get_cipher_frequencies(shifted_string)
            correlations = [frequencies[letter]*cipher_frequencies[letter] for letter in alphabet]
            sums[shift] = sum(correlations)
        likely_key = max(sums,key=sums.get)
        return self.decrypt(ciphertext,likely_key)


class Viginere(Cipher):

    def encrypt(self,plaintext,keyword):
        keyword_cycle = cycle(keyword)
        encrypted_list = [letters[(nums[letter]+nums[next(keyword_cycle)])%26] for  letter in plaintext]
        return ''.join(encrypted_list)

    def decrypt(self,ciphertext,keyword):
        keyword_cycle = cycle(keyword)
        decrypted_list = [letters[(nums[letter]-nums[next(keyword_cycle)])%26] for  letter in ciphertext]
        return ''.join(decrypted_list)
    
    def crack(self,ciphertext,plaintext=None):
        pass

class Hill(Cipher):

    def encrypt(self,plaintext,A):
        text_vector = self._ConvertStringToVector(plaintext)
        encrypted_vector = (text_vector.dot(A.transpose()))%26
        return self._ConvertVectorToString(encrypted_vector)

    def decrypt(self,ciphertext,A):
        key_inv = self._FindKeyInverse(A)
        text_vector = self._ConvertStringToVector(ciphertext)
        decrypted_vector = (text_vector.dot(key_inv.transpose()))%26
        return self._ConvertVectorToString(decrypted_vector)

    def crack(self,ciphertext,plaintext=None):
        pass

    def _FindKeyInverse(self,A):
        det = int(np.linalg.det(A))
        a_inv = modInverse(det,26)
        A_inv = np.array([[A[1,1],-A[0,1]],[-A[1,0],A[0,0]]])
        return (a_inv*A_inv)%26
    
    def _ConvertStringToVector(self,text):
        text_list = [nums[letter] for letter in text]
        num_rows = len(text_list) // 2
        text_array = np.array(text_list)
        return text_array.reshape((num_rows,2))

    def _ConvertVectorToString(self,vec):
        converted_list = vec.reshape(1,vec.shape[0]*vec.shape[1]).tolist()[0]
        converted_string = [letters[num] for num in converted_list]
        return ''.join(converted_string)

class Affine(Cipher):

    def encrypt(self,plaintext,a,b):
        alphabet=string.ascii_uppercase
        shifted_alphabet = [letters[(nums[letter]*a+b)%26] for letter in alphabet]
        table = str.maketrans(alphabet, ''.join(shifted_alphabet))
        return plaintext.translate(table)

    def decrypt(self,ciphertext,a_inv,b):
        alphabet = string.ascii_uppercase
        shifted_alphabet = [letters[a_inv*(nums[letter]-b)%26] for letter in alphabet]
        table = str.maketrans(alphabet, ''.join(shifted_alphabet))
        return ciphertext.translate(table)

    def crack(self,ciphertext,plaintext=None):
        pass
        
if __name__=="__main__":
    ciphertext='ALIIP'
    runner = Shift()
    for shift in range(26):
        print("text: " + runner.decrypt(ciphertext,shift) + " shift: " + str(shift))

