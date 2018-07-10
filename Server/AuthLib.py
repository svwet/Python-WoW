'''
implementation of WoW 1.12 server SRP6 protocol
https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol#Implementation_example_in_Python
http://srp.stanford.edu/design.html
'''
import functools
import operator
import os
import hashlib
import cryptography
import codecs

from cryptography.hazmat.backends.openssl import backend

#hashing sha1 algo
sha1 = hashlib.sha1


#OpenSSL primitives for work with "Big Numbers" https://www.openssl.org/docs/manmaster/crypto/bn.html
BN_new     = backend._lib.BN_new
BN_CTX_new = backend._lib.BN_CTX_new
BN_bin2bn  = backend._lib.BN_bin2bn 
BN_mod_exp = backend._lib.BN_mod_exp
BN_mod     = backend._lib.BN_mod
BN_mul     = backend._lib.BN_mul
BN_add     = backend._lib.BN_add
BN_bn2bin  = backend._lib.BN_bn2bin
RAND_bytes = backend._lib.RAND_bytes
BN_to_int  = backend._bn_to_int
#constructor of pointers to C arrays
Cnew       = backend._ffi.new  
#python-list-like interface to access to C arrays
buffer     = backend._ffi.buffer
null       = backend._ffi.NULL





#service functions

def reverseC(ar):
    '''
    Reverse of C array. Input is pointer to C array. Works like python list reverse. With side effects. 
    >>> b = Cnew('char[]', 10)
    >>> buffer(b)[:] = bytes(range(10))
    >>> reverseC(b)
    >>> [int(i) for i in buffer(b)[:]]
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    '''
    ar1 = [i for i in buffer(ar)[:]]
    ar1.reverse()
    buffer(ar)[:] = bytes(ar1)

def blockCopy(ar1, ofs1, ar2, ofs2, count):
    '''
    Copies a specified number of bytes from a source array starting at a 
    particular offset to a destination array starting at a particular offset. There is indexation from zero.
    Between arrays of the same size:
    >>> ar1 = Cnew('char[]', 10)
    >>> buffer(ar1)[:] = bytes([1 for x in range(10)])
    >>> ar2 = Cnew('char[]', 10)
    >>> buffer(ar2)[:] = bytes([2 for x in range(10)])
    >>> start_pos_ar1 = 3
    >>> start_pos_ar2 = 3
    >>> count = 4
    >>> blockCopy(ar1, start_pos_ar1, ar2, start_pos_ar2, count)
    >>> [i for i in buffer(ar2)[:]]
    [2, 2, 2, 1, 1, 1, 1, 2, 2, 2]
    '''
    buffer(ar2)[ofs2:ofs2+count] = buffer(ar1)[ofs1:ofs1+count]
    

#combine function from https://github.com/mangosvb/serverZero/blob/master/Server/RealmServer/AuthEngineClass.vb
def Combine(b1, b2):
    '''
    >>> ar1 = Cnew('char[]', 10)
    >>> buffer(ar1)[:] = bytes([1 for x in range(10)])
    >>> ar2 = Cnew('char[]', 10)
    >>> buffer(ar2)[:] = bytes([2 for x in range(10)])
    >>> [i for i in buffer(Combine(ar1, ar2))[:]]     
    [1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2]
    '''
    if (len(b1) == len(b2)):
        buffer1 = Cnew('char[]', (len(b1) + len(b2)) ) 

        buffer(buffer1)[:] = bytes(
            list(
                functools.reduce(
                    operator.add,
                    zip(buffer(b1)[:], buffer(b2)[:])))[:])
        
        return buffer1
    else: return None


def Split(bo):
    '''
    >>> ar = Cnew('char[]', 10)
    >>> buffer(ar)[:] = bytes([x for x in range(10)])
    >>> [i for i in buffer(Split(ar)[0])[:]]
    [0, 2, 4, 6, 8]
    >>> [i for i in buffer(Split(ar)[1])[:]]
    [1, 3, 5, 7, 9]
    '''

    buffer2 = Cnew('char[]', int(len(bo) / 2))
    buffer3 = Cnew('char[]', int(len(bo) / 2)) 

    buffer(buffer2)[:] = buffer(bo)[:][::2]  #even
    buffer(buffer3)[:] = buffer(bo)[:][1::2] #odd
    return (buffer2, buffer3)
    
    
#Constants



# ...A and B are random one time ephemeral keys of the user and host respectively...
def calculateB(bNg, bNn, bNk, bNv):

    PublicB =  Cnew('char[]', 32)
    b = Cnew('char[]', 20)
    #RAND_bytes(b, 20)
    buffer(b)[:] = bytes([27,240, 101, 209, 76, 3, 187, 19, 210, 192, 139, 227, 243, 223, 184, 36, 228, 74, 182, 91])
    ptr1      = BN_new()
    ptr2      = BN_new()
    ptr3      = BN_new()
    bnPublicB = BN_new()
    ptr5      = BN_CTX_new()
    reverseC(b)
    bNb = BN_bin2bn(b, len(b), null)
    reverseC(b)
    #BN_mod_exp() computes a to the p-th power modulo m (r=a^p % m).
    #This function uses less time and space than BN_exp().
    BN_mod_exp(ptr1, bNg, bNb, bNn, ptr5)
    #BN_mul() multiplies a and b and places the result in r (r=a*b).
    #r may be the same BIGNUM as a or b. For multiplication by powers of 2, use BN_lshift.
    BN_mul(ptr2, bNk, bNv, ptr5)
    BN_add(ptr3, ptr1, ptr2)
    BN_mod(bnPublicB, ptr3, bNn, ptr5)
    BN_bn2bin(bnPublicB, PublicB)
    reverseC(PublicB)
    return (b, bNb, PublicB)

def calculateK(s):

    s1, s2 = Split(s) #split s to 2 16-byte chunks
    #sha1 hashes of s1 and s2
    h1, h2 = Cnew('char[]', 20), Cnew('char[]', 20)
    
    buffer(h1)[:] = sha1(buffer(s1)[:]).digest()
    buffer(h2)[:] = sha1(buffer(s2)[:]).digest()
    return Combine(h1, h2)




def calculateS(bna, bNv, bNu, bNn, bNb):
    ptr1  = BN_new()
    ptr2  = BN_new()
    bns   = BN_new()
    ptr5  = BN_CTX_new()
    s     = Cnew('char[]',32) 
    BN_mod_exp(ptr1, bNv, bNu, bNn, ptr5)
    BN_mul(ptr2, bna, ptr1, ptr5)
    BN_mod_exp(bns, ptr2, bNb, bNn, ptr5)
    BN_bn2bin(bns, s)
    reverseC(s)
    return s
    
# Random scrambling parameter
def calculateU(a, PublicB):
    buffer1  = Cnew ('char[]',(len(a) + len(PublicB)))
    blockCopy(a, 0, buffer1, 0, len(a))
    blockCopy(PublicB, 0, buffer1, len(a), len(PublicB))
    u = Cnew ('char[]',20)
    buffer(u)[:] = sha1(bytes(buffer(buffer1)[:])).digest()
    reverseC(u)
    bNu = BN_bin2bn(u, len(u), null)
    reverseC(u)
    reverseC(a)
    bNa = BN_bin2bn(a, len(a), null)
    reverseC(a)
    return (bNa, bNu)
    
# Password verifier (server side)
def calculateV(bNg, bNx, bNn, bNk):
    bNv = BN_new()
    ptr1  = BN_CTX_new()
    BN_mod_exp(bNv, bNg, bNx, bNn, ptr1)
    return bNv

#Private key .derived from p(password) and s(users salt) 
def calculateX(pwHash, Salt, g, k, N):
    buffer3 = Cnew('char[]', 20)
    buffer5 = Cnew('char[]', (len(Salt) + 20) )
    blockCopy(pwHash, 0, buffer5, len(Salt), 20)
    blockCopy(Salt,   0, buffer5, 0,         len(Salt))
    buffer(buffer3)[:] = sha1(bytes(buffer(buffer5)[:])).digest()
    reverseC(buffer3)
    bNx = BN_bin2bn(buffer3, len(buffer3), null)
    reverseC(g)
    bNg = BN_bin2bn(g, len(g), null)
    reverseC(g)
    reverseC(k)
    bNk = BN_bin2bn(k, len(k), null)
    reverseC(k)
    reverseC(N)
    bNn = BN_bin2bn(N, len(N), null)
    reverseC(N)
    return (bNg, bNx, bNn, bNk)


def calculateM1(username, N, g, Salt, a, PublicB, ssHash):
    nHash    = Cnew('char[]', 20)
    gHash    = Cnew('char[]', 20) 
    ngHash   = Cnew('char[]', 20)
    userHash = Cnew('char[]', 20)

    buffer(nHash)[:]    = sha1(buffer(N)[:]).digest()
    buffer(gHash)[:]    = sha1(buffer(g)[:]).digest()
    buffer(userHash)[:] = sha1(buffer(username)[:].split(b'\00')[0]).digest()

    
    buffer(ngHash)[:] = bytes([i ^ j for i, j in zip(buffer(nHash)[:], buffer(gHash)[:])])

    temp =   buffer(ngHash)[:] \
           + buffer(userHash)[:] \
           + buffer(Salt)[:] \
           + buffer(a)[:] \
           + buffer(PublicB)[:] \
           + buffer(ssHash)[:]

    M1 = Cnew('char[]', 20) 
    buffer(M1)[:] = sha1(temp).digest()
    return M1

def calculateM2(a, m1Loc, ssHash):


    buffer1 = Cnew("char[]", ((len(a) + len(m1Loc)) + len(ssHash)))
    blockCopy(a, 0, buffer1, 0, len(a))
    blockCopy(m1Loc, 0, buffer1, len(a), len(m1Loc))
    blockCopy(ssHash, 0, buffer1, (len(a) + len(m1Loc)), len(ssHash))
    M2 = Cnew('char[]', 20) 
    buffer(M2)[:] = sha1(buffer(buffer1)[:]).digest()
    return M2


class SRP6Engine:
    '''
    Example variables witch emulate 1-st client logon request PLAYER:PLAYER. 
    Login value from request, salt and pwhash stored in database.
    >>> Salt = [173, 208, 58,  49,\
                210, 113, 20,  70,\
                117, 242, 112, 126,\
                80,  38,  182, 210,\
                241, 134, 89,  153,\
                118, 2,   80,  170,\
                185, 69,  224, 158,\
                221, 42,  163, 69]
    >>> login = bytes(map(lambda x: int(x,16),\
             ['50','4c','41','59','45','52']))
    >>> pwHash = map(lambda x: int(x,16),\
             ['3c','e8','a9','6d','17','c5','ae','88',\
              'a3','06','81','02','4e','86','27','9f',\
              '1a','38','c0','41'])
    >>> s = AuthSession()

    Calculate some values:
    >>> s.process_rs_logon_challenge(login, pwHash, Salt)

    Check is values exists:
    >>> all([s.bNg, s.bNx, s.bNn, s.bNk,s.bNv, s.b, s.bNb, s.PublicB])
    True
    
    Recieving second packet from client with a.
    
    >>> a = list(map(lambda x: int(x,16),\
        '92-B5-A2-EE-2F-48-3A-55-C0-26-6A-4B-0D-33-76-E7-AB-62-62-85-41-7D-52-41-DB-3F-1F-72-57-E0-95-5E'.split('-')))

    #>>> a = map(lambda x: int(x,16),\
    #            ['ff','be','72','5b','b2','1e','50','14',\
    #             'c8','8b','48','1c','6b','84','b7','20',\
    #             'a1','8b','be','6f','d0','43','c4','c6',\
    #             'f6','10','02','a7','98','0b','04','08'])
    
    Calculate second part of auth.
    >>> s.process_rs_logon_proof(a)

    Check results are exists:
    >>> all([s.bNa, s.bNu, s.s, s.ssHash, s.M1, s.M2])
    True

    >>> hexize = lambda x: hex(int(x))
    >>> print('account', list(map(hexize,login)))
    >>> print('a', list(map(hexize,a)))
    >>> print('Hash', list(map(hexize,buffer(s.pwHash)[:])))
    >>> print('PublicB', list(map(hexize,buffer(s.PublicB)[:])))
    >>> print('ssHash', list(map(hexize,buffer(s.ssHash)[:])))
    >>> print('M1', list(map(hexize,buffer(s.M1)[:])))
    >>> print('M2', list(map(hexize,buffer(s.M2)[:])))

    '''
    #default values
    d_g = 7
    d_k = 3
    d_N = [137, 75,  100, 94,\
           137, 225, 83,  91,\
           189, 173, 91,  139,\
           41,  6,   80,  83,\
           8,   1,   177, 142,\
           191, 191, 94,  143,\
           171, 60,  130, 135,\
           42,  62,  155, 183]
    d_Salt = [173, 208, 58,  49,\
              210, 113, 20,  70,\
              117, 242, 112, 126,\
              80,  38,  182, 210,\
              241, 134, 89,  153,\
              118, 2,   80,  170,\
              185, 69,  224, 158,\
              221, 42,  163, 69]
    def __init__(self, g=d_g, k=d_k, N=d_N):
        self.g = Cnew('char[]', 1)
        self.k = Cnew('char[]', 1)
        self.N = Cnew('char[]', 32)
        

        buffer(self.g)[:] = bytes([g])
        buffer(self.k)[:] = bytes([k])
        buffer(self.N)[:] = bytes(N)



    def process_rs_logon_challenge(self, login, pwHash, Salt=d_Salt):
        self.login = Cnew('char[]', 20)
        buffer(self.login)[:len(login)] = bytes(login, 'ascii')
        self.pwHash = Cnew('char[]', 20)
        buffer(self.pwHash)[:] = codecs.decode(pwHash, 'hex')
        
        self.Salt = Cnew('char[]', 32)
        buffer(self.Salt)[:] = bytes(Salt)

        self.bNg, self.bNx, self.bNn, self.bNk = calculateX(self.pwHash,
                                                            self.Salt,
                                                            self.g,
                                                            self.k,
                                                            self.N)
        
        self.bNv = calculateV(self.bNg,
                              self.bNx,
                              self.bNn,
                              self.bNk)
        
        self.b, self.bNb, self.PublicB = calculateB(self.bNg,
                                                    self.bNn,
                                                    self.bNk,
                                                    self.bNv)
        
        self.status = 'client challenge calculated'

    def process_rs_logon_proof(self,a):
        self.a = Cnew('char[]', 32)
        buffer(self.a)[:] = bytes(a) 
        self.bNa, self.bNu = calculateU(self.a, self.PublicB)                              
        self.s        = calculateS(self.bNa,
                                   self.bNv,
                                   self.bNu,
                                   self.bNn,
                                   self.bNb)                   
        self.ssHash   = calculateK(self.s)                                         
        self.M1       = calculateM1(self.login,
                                    self.N,
                                    self.g,
                                    self.Salt,
                                    self.a,
                                    self.PublicB,
                                    self.ssHash)
        self.M2       = calculateM2(self.a, self.M1, self.ssHash)
        self.status = 'client proof calculated'

    def get_raw_challenge_values(self):
        return {
            'N': buffer(self.N)[:],
            'k': buffer(self.k)[:],
            'g': buffer(self.g)[:],
            'b': buffer(self.b)[:],
            'PublicB': buffer(self.PublicB)[:],
            'Salt': buffer(self.Salt)[:],
            'login':buffer(self.login)[:],
            'pwHash': buffer(self.pwHash)[:]}

    def get_M(self):
        return (buffer(self.M1)[:],buffer(self.M2)[:])
        

if __name__ == '__main__':
    import doctest
    doctest.testmod()

