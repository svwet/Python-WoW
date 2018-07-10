import operator
import os
import struct
from functools import reduce
from cryptography.hazmat.backends.openssl import backend

RAND_bytes = backend._lib.RAND_bytes
Cnew       = backend._ffi.new  
buffer     = backend._ffi.buffer



def align(byte_arr, length):
    'Add null bytes in right of bytestring, sum size = length'
    return byte_arr + bytes(length - len(byte_arr))

class Packet:
    '''WoW packet implementation'''
    def __init__(self, raw=b''):
        self.raw = raw
        self.raw_iter = iter(raw)
        self.nb = self.raw_iter.__next__ #next byte from raw request
        
    def decode(self, raw):
        '''if packet from client need to decode it to python values'''
        pass

    def encode(self, **kwargs):
        '''if packet to client need to encode it from python values'''
        pass

    def reduce_n_bytes_by(self, iterator, func, n):
        #just repeat interator 4 times and concatenate chars into string
        return reduce(func, map(lambda x: bytes([iterator.__next__()]), range(n)))

class RS_CLIENT_LOGON_CHALLENGE(Packet):
    '''
    Client->Server
    When client enter Account name, Account password and click Login 
    WoW client send this package. 

    In this case I enter PLAYER:PLAYER. First packet in python bytes 
    representation looks this:
    >>> raw = [0,   3,   36,  0,   87, 111, 87,  0]   + \
              [1,   12,  1,   243, 22, 54,  56,  120] + \
              [0,   110, 105, 87,  0,  83,  85,  110] + \
              [101, 180, 0,   0,   0,  192, 168, 1]   + \
              [4,   6,   80,  76,  65, 89,  69,  82]
    >>> raw = bytes(raw)
    >>> packet = RS_CLIENT_LOGON_CHALLENGE(raw=raw).decode()
    >>> packet 
    'PLAYER'
    '''
        
    def decode(self):
        '''
        Content of RS_CLIENT_LOGON_CHALLENGE is
        uint8   cmd;
        uint8   error;
        uint16  size;
        uint8   gamename[4];
        uint8   version1;
        uint8   version2;
        uint8   version3;
        uint16  build;
        uint8   platform[4];
        uint8   os[4];
        uint8   country[4];
        uint32  timezone_bias;
        uint32  ip;
        uint8   I_len;
        uint8   I[50];        

        Info from here http://www.arcemu.org/wiki/Client_Logon_Challenge#I
        '''
        
        cmd      = self.nb()
        error    = self.nb()
        size     = int(self.nb()) + int(self.nb())
        gamename = self.reduce_n_bytes_by(self.raw_iter, operator.add,4) 
        version1 = self.nb()
        version2 = self.nb()
        version3 = self.nb()
        build    = chr(self.nb()) + chr(self.nb())
        platform = self.reduce_n_bytes_by(self.raw_iter, operator.add,4) 
        os       = self.reduce_n_bytes_by(self.raw_iter, operator.add,4) 
        country  = self.reduce_n_bytes_by(self.raw_iter, operator.add,4)
        timezone_bias = self.reduce_n_bytes_by(self.raw_iter, operator.add,4) 
        ip       = '.'.join(map(lambda x:str(self.nb()), range(4)))
        I_len    = int(self.nb())
        I        = self.reduce_n_bytes_by(self.raw_iter, operator.add,I_len)
        return str(I, 'ascii')


class RS_SERVER_LOGON_CHALLENGE(Packet):
    '''
    Server->Client
    This is first answer of the server.

    uint8   cmd;
    uint8   error;
    uint8   unk2;
    uint8   B[32];
    uint8   g_len;
    uint8   g;
    uint8   N_len;
    uint8   N[32];
    uint8   s[32];
    uint8   unk3[16];
    uint8   unk4;

    >>> test = RS_SERVER_LOGON_CHALLENGE()
    >>> test.encode(b'1', b'2', b'3', b'4')
    >>> 

    '''

    def encode(self, PublicB, g, N, Salt):

        self.raw += bytes([0]) #cmd
        self.raw += bytes([0]) #error. no error == 0
        self.raw += bytes([0]) #unknown
        self.raw += align(PublicB, 32)   #B
        self.raw += bytes([len(g)]) #length g
        self.raw += g # g
        self.raw += bytes([32])#length N. always should be 32
        self.raw += align(N, 32)# N
        self.raw += align(Salt, 32)# s
        crcsalt = Cnew('char[]',16)
        RAND_bytes(crcsalt, 16)
        self.raw += buffer(crcsalt)[:]
        #self.raw += os.urandom(16) #unknown
        self.raw += bytes([0])
        return self.raw
        
class RS_CLIENT_LOGON_PROOF(Packet):
    '''Client->Server
    Second client request.
    '''
    
        
    def decode(self):
        '''
        Content of RS_CLIENT_LOGON_PROOF is
        uint8   cmd;
        uint8   A[32];
        uint8   M1[20];
        uint8   crc_hash[20];
        uint8   number_of_keys;
        uint8   unk;

        Info from  http://www.arcemu.org
        '''
        cmd      = self.nb()
        A        = self.reduce_n_bytes_by(self.raw_iter, operator.add,32) 
        M1       = self.reduce_n_bytes_by(self.raw_iter, operator.add,20)
        crc_hash = self.reduce_n_bytes_by(self.raw_iter, operator.add,20)
        number_of_keys = self.nb()
        unk      = self.nb()
        return (A, M1)

class RS_SERVER_LOGON_PROOF(Packet):
    '''
    Server->Client
    This is second answer of the server.
    uint8   cmd;
    uint8   error;
    uint8   M2[20];
    uint32  accountflags;
    '''

    def encode(self, M2):
        self.raw = bytes([1,0]) + M2 + bytes(4)

        
class RS_CLIENT_REALM_LIST(Packet):
    '''Client->Server
    Client asks server what realms are avaiable.
    Packet contains:
    uint8 cmd;
    '''
        
    def decode(self):
        '''
        Content of RS_CLIENT_REALM_LIST is only '10' byte and 4 null bytes.
        Info from  wireshark dump
        '''
        cmd      = self.nb()
        return int(cmd)

    
class RS_SERVER_REALM_LIST(Packet):
    '''Server->Client
    Server answer what realms he have.
    you can find docs here https://github.com/mangosvb/serverZero/blob/28459d39d760e97ef85143ceae3e978c7886fba8/Server/RealmServer/RealmServer.vb

    Packet contains:
    uint8 cmd; - 10 for this packet
    uint16 packet_size; bytes from next byte to end
    uint32 unk1; four null bytes
    uint16 number_of_realms;
    uint8 type; 0 if ok
    uint8 status; 0 if online
    uint8 color; 0
    uint8[8] name; 
    uint8[15] server_socket; 
    uint32 population_level; 
    uint8 number_of_charachters;
    uint8 timezone;
    uint32 unk2;
    
    '''
        
    def encode(self, realms):
        def align(byte_arr, length):
            'Add null bytes in right of bytestring, '
            return byte_arr + bytes(length - len(byte_arr))
        cmd = bytes([16]) 
        unk1 = bytes(4) 
        
        number_of_realms = struct.pack('h', len(realms))

        body = b''
        for realm in realms:
            body += bytes([realm['type']])
            body += bytes([realm['isLocked']])
            body += bytes(1) #2 unknown bytes
            body += bytes([realm['color']])
            body += bytes(realm['name'], 'ascii') + bytes(1)
            body += bytes(realm['address'], 'ascii') \
                    + bytes(':', 'ascii')\
                    + bytes(str(realm['game_port']), 'ascii')\
                    + bytes(1)

            #float number to byte representation
            body += struct.pack('f', realm['population'])
            body += bytes([realm['characters_count']])
            body += bytes([realm['timezone']])
            body += bytes(1)

        body += bytes([2,0])
            
        packet_size = struct.pack('h', len(unk1 + number_of_realms + body))
        self.raw = cmd + packet_size + unk1 + number_of_realms + body
        return self.raw




    

if __name__ == '__main__':
    import doctest
    doctest.testmod()
    
