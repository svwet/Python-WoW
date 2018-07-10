from AuthLib import SRP6Engine
from WoWPackets import *
from CommPackets import *
import configparser
import sys
from models import *
from database import db_session
import time

from twisted.python import log
from twisted.internet.protocol import Factory, ClientFactory, Protocol
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor


if len(sys.argv) < 2: raise Exception(
        'Give the config file! Defalut run is:\n'+\
        'python Server/RealmServer.py RealmServer.ini\n'+\
        'Default RealmServer.ini in root progect directory.')

else: confile = sys.argv[1]

config = configparser.ConfigParser()
config.read(confile)

realms = [{'type'             : int(c['type']),
           'isLocked'         : int(c['isLocked']),
           'color'            : int(c['color']),
           'name'             : c['name'],
           'address'          : c['address'],
           'game_port'        : int(c['game_port']),
           'comm_port'        : int(c['comm_port']),
           'population'       : 1,
           'characters_count' : 16,
           'timezone'         : int(c['timezone'])}
          for c in [config[k] for k in config.keys() if k.startswith('world')]]


class CommSession(Protocol):

    def __init__(self):
        self.state = ''
        
    def connectionMade(self):
        self.transport.write(ARE_YOU_ALIVE().raw)

    def connectionLost(self, reason):
        print('connection broken because', reason)
        
    def dataReceived(self, data):
        
        if data == YES_I_AM_ALIVE().raw:
            self.state = 'alive'
            
        elif data == NO_I_AM_DEAD().raw:
            self.state = 'dead'

        print('packet recieved from',
              self.transport.getPeer(),
              'state is', self.state,
              'and contain', data)
            
        
class AuthSession(LineReceiver):
    delimiter = b''
    def __init__(self, connections):
        self.setRawMode()
        self.connections = connections
        self.SRP6Engine = SRP6Engine()
        self.state = "CHALLENGE"

    def connectionMade(self):
        peer = self.transport.getPeer()
        if peer.type=='TCP':
            self.peer = peer.host
        else:
            self.loseConnection()
            return
        if self.peer in self.connections:
            self.loseConnection()
            return
        
    def connectionLost(self, reason):
        if self.peer in self.connections:
            del self.connections[self.peer]

    def rawDataReceived(self, data):
        print('packet recieved from', self.transport.getPeer(),
              'state is', self.state,
              'and contain', data)

        #request from one of world servers
        if self.peer in [realm['address'] for realm in realms]\
           and data[0] == 255:
            self.handle_WORLDSERVER(data)
            self.state = "WORLDSERVER"
        #client request types 
        elif  self.state == "CHALLENGE":
            self.handle_CHALLENGE(data)
        elif self.state == "PROOF":
            self.handle_PROOF(data)
        elif self.state == "REALMLIST":
            self.handle_REALMLIST(data)
        else:
            self.handle_ERROR(data, state)

    def handle_CHALLENGE(self, data):

        username = RS_CLIENT_LOGON_CHALLENGE(data).decode()
        account = db_session.query(Account)\
                    .filter(Account.username == username)\
                    .first()
        if account:
            pwHash = account.pwHash
        else: raise Exception("Guy {0} tryed to log in"\
                              .format([username]) )
        self.SRP6Engine\
            .process_rs_logon_challenge(username, pwHash)
        resp_dict = self.SRP6Engine.get_raw_challenge_values()
        rslc      = RS_SERVER_LOGON_CHALLENGE()
    
        rslc.encode(resp_dict['PublicB'],
                    resp_dict['g'],
                    resp_dict['N'],
                    resp_dict['Salt'])
        self.connections[self.peer] = self
        self.state = "PROOF"
        self.sendLine(rslc.raw)
        
    def handle_PROOF(self, data):

        A, M1 = RS_CLIENT_LOGON_PROOF(data).decode()
        self.SRP6Engine.process_rs_logon_proof(A)
        our_M1, M2 = self.SRP6Engine.get_M()
        if not M1 == our_M1:
            print('this guy not registered')
            self.transport.loseConnection()
            return None
        rslp = RS_SERVER_LOGON_PROOF()
        rslp.encode(M2)
        self.state = "REALMLIST"
        self.sendLine(rslp.raw)

    def handle_REALMLIST(self,data):

        if RS_CLIENT_REALM_LIST(data).decode() != 16:
            #0x10 command is realmlist request. 
            return
        rsrl = RS_SERVER_REALM_LIST()
        print('realms',realms)
        rsrl.encode(realms)
        self.sendLine(rsrl.raw)

    def handle_ERROR(self, data, state):
        print(self.peer,
              'send this',
              data,
              'while it state was',
              state,
              'and it is not ok')
        
    def handle_WORLDSERVER(self, data):
        print('data from world server ', self.peer, 'is', data)

        
class RealmServer(Factory):
    def __init__(self):
        self.connections = {}
    def buildProtocol(self, addr):
        return AuthSession(self.connections)

    
class Communicator(ClientFactory):
    def startedConnecting(self, connector):
        print('Started to connect.')

    def buildProtocol(self, addr):
        return CommSession()

    def clientConnectionLost(self, connector, reason):
        print('Lost connection.  Reason:', reason)

    def clientConnectionFailed(self, connector, reason):
        print('Connection failed. Reason:', reason)



if __name__ == '__main__':
    log.startLogging(sys.stdout)
    comm = Communicator()
    for realm in realms:
        reactor.connectTCP(realm['address'], realm['comm_port'], comm)
        
    realm_port = int(config['net']['realm_port'])
    server = RealmServer()        
    reactor.listenTCP(realm_port, server)
    reactor.run()
