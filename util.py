import collections
import string
import numpy as np

'''collection of useful dictionaries, constantts, and functions for ciphers.'''

alphabet = string.ascii_uppercase
nums = {x:y for x,y in zip(alphabet,range(0,26))}
letters = {y:x for x,y in zip(alphabet,range(0,26))}
frequencies = collections.OrderedDict({'E':12.51,'T':9.25,'A':8.04,'O':7.60,'I':7.26,'N':7.09,'S':6.54,'R':6.12,'H':5.49,'L':4.14,'D':3.99,'C':3.06,'U':2.71,'M':2.53,'F':2.30,'P':2.00,'G':1.96,'W':1.92,'Y':1.73,'B':1.54,'V':0.99,'K':0.67,'X':0.19,'J':0.16,'Q':0.11,'Z':0.09})


def Sieve(n): 
      
    # Create a boolean array "prime[0..n]" and initialize 
    #  all entries it as true. A value in prime[i] will 
    # finally be false if i is Not a prime, else true. 
    prime = [True for i in range(n+1)] 
    p = 2
    while (p * p <= n): 
        # If prime[p] is not changed, then it is a prime 
        if (prime[p] == True): 
              
            # Update all multiples of p 
            for i in range(p * 2, n+1, p): 
                prime[i] = False
        p += 1
      
    # collect all prime numbers 
    primes = []
    for p in range(2, n): 
        if prime[p]: 
            primes.append(p)
    for i in range(len(primes)):
        for j in range(i,len(primes)):
            if primes[i]*primes[j]==n:
                return primes[i],primes[j]


def modExponentiate(x,power,mod):
    val = x
    for i in range(2,power+1):
        val = val * x % mod
    return val


    
            
def modInverse(a, m) : 
    a = a % m
    for x in range(1, m):
        if ((a * x) % m == 1):
            return x 
    return 1

def remove_spaces(ciphertext):
    return ciphertext.replace('\n','').replace(' ','')

def remove_spaces_from_file(file_):
    return open(file_).read().replace('\n','').replace(' ','')

def get_cipher_frequencies(ciphertext):
    cipher_frequencies = dict.fromkeys(alphabet,0)
    cipher_len = len(ciphertext)
    for letter in ciphertext:
        cipher_frequencies[letter]+=1.0/cipher_len
    return collections.OrderedDict(cipher_frequencies)

def get_letter_counts(ciphertext):
    '''same as get_cipher_frequences but does not divide by cipher_len'''
    cipher_frequencies = dict.fromkeys(alphabet,0)
    for letter in ciphertext:
        cipher_frequencies[letter]+=1
    return list(cipher_frequencies.values())

def get_repeated_sequences(ciphertext,k):
    sequences = collections.defaultdict(int)
    for i in range(len(ciphertext)-k+1):
        clip = ciphertext[i:i+k]
        sequences[clip]+=1
    return sorted(sequences,reverse=True,key=sequences.get)

def get_double_letters(ciphertext):
    doubles = collections.defaultdict(int)
    for i in range(len(ciphertext)-1):
        clip = ciphertext[i:i+2]
        if clip[0]==clip[1]:
            doubles[clip]+=1
    return sorted(doubles,reverse=True,key=doubles.get)
    
def IC(ciphertext):
    freq = np.array(get_letter_counts(ciphertext))
    numerator = sum(freq * (freq-1))
    return numerator / (len(ciphertext)*(len(ciphertext)-1))

def estimate_N(ciphertext):
    return 0.0275/(IC(ciphertext)-0.0385)

def find_N(ciphertext,iterations=12):
    IC_by_iteration = []
    ICs=[]
    for i in range(2,iterations):
        for j in range(i):
            string = ciphertext[j::i] #easy way to split the string
            ICs.append(IC(string))
        IC_by_iteration.append(np.mean(ICs))
    #print(IC_by_iteration)
    return np.argmax(IC_by_iteration) +2 #we start at key length 2

if __name__=="__main__":
    ciphertext = "IYMECGOBDOJBSNTVAQLNBIEAOYIOHVXZYZYLEEVIPWOBBOEIVZHWUDEAQALLKROCUWSWRYSIUYBMAEIRDEFYYLKODKOGIKPHPRDEJIPWLLWPHRKYMBMAKNGMRELYDPHRNPZHBYJDPMMWBXEYOZJMYXNYJDQWYMEOGPYBCXSXXYHLBELLEPRDEGWXLEPMNOCMRTGQQOUPPEDPSLZOJAEYWNMKRFBLPGIMQAYTSHMRCKTUMVSTVDBOEUEEVRGJGGPIATDRARABLPGIMQDBCFWXDFAWUWPPMRGJGNOETGDMCIIMEXTBEENBNICKYPWNQBLPGIMQOELICMRCLACMV"
    print()
    print(estimate_N(ciphertext))
    print(find_N(ciphertext,20))
