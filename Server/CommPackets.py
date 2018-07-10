# this file contains packets of internal communication between servers

class CommPacket:
    '''Network package for internal communication between servers'''

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

class ARE_YOU_ALIVE(CommPacket):
    '''
    Request from one server to another. 
    '''

    def __init__(self):
        self.raw = bytes([255, 0])
        

class YES_I_AM_ALIVE(CommPacket):
    '''
    Response for reauest AreYouAlive meaning "yes" .
    '''
    def __init__(self):
        self.raw = bytes([255, 1])


class NO_I_AM_DEAD(CommPacket):
    '''
    Response for request AreYouAlive meaning "yes" .
    '''
    def __init__(self):
        self.raw = bytes([255, 2])


class THIS_GUY_WANNA_PLAY(CommPacket):
    '''
    When somebody login on RealmServer
    RealmServer tell about this to GameServer

    >>> THIS_GUY_WANNA_PLAY('192.168.1.3').raw
    b'\xffd192.168.1.3'
    '''
    
    def __init__(self, ip):
        
        self.raw = bytes([255, 100]) + bytes(ip, 'ascii')
    
if __name__ == '__main__':
    import doctest
    doctest.testmod()

