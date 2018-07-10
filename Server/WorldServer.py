import configparser
import sys
import socket
from CommPackets import *

from twisted.python import log
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor

if len(sys.argv) < 2: raise Exception(
        'Give the config file! Defalut run is:\n'+\
        'python Server/WorldServer.py WorldServer.ini\n'+\
        'Default WorldServer.ini in root progect directory.')
else: confile = sys.argv[1]

config = configparser.ConfigParser()
config.read(confile)

game_port  = int(config['net']['game_port'])
comm_port  = int(config['realm']['comm_port'])
realm_addr = config['realm']['address']
        
class GameSession(LineReceiver):
    delimiter = b''
    def __init__(self, alive, connections):
        self.setRawMode()
        self.alive = alive
        self.connections = connections

    def connectionMade(self):
        self.peer = self.transport.getPeer()
        
    def connectionLost(self, reason):
        if self.peer in self.connections:
            del self.connections[self.peer]

    def rawDataReceived(self, data):
        print('packet recieved from', self.peer,
              'packet contains', data)
        # 255 is command byte for internal conversation
        # between servers
        # this command should be fror realm server address
        if data[0]       == 255\
           and self.peer.host == realm_addr: 
            self.handle_SERVER(data)
        else: self.handle_GAME(data)

    def handle_SERVER(self, data):
        print('handle server')
        # ARE_YOU_ALIVE packet
        if data == bytes([255,0]):
            if self.alive:
                self.sendLine(YES_I_AM_ALIVE().raw)
            else:
                self.sendLine(NO_I_AM_DEAD().raw)
        
    def handle_GAME(self, data):
        pass
    
    

class WorldServer(Factory):
    def __init__(self):
        self.alive = True
        self.connections = {}

    def buildProtocol(self, addr):
        return GameSession(self.alive, self.connections)

    
if __name__ == '__main__':
    log.startLogging(sys.stdout)
    server = WorldServer()
    reactor.listenTCP(comm_port, server)
    reactor.listenTCP(game_port, server)
    reactor.run()
