#database models for autogenerate and manage tables in database

from sqlalchemy import Column, ForeignKey, Integer, String, Time
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

    
    
class Account(Base):
    __tablename__ = 'account'
    id = Column(Integer, primary_key = True)
    username = Column(String(50))
    pwHash   = Column(String(40))
    gmlevel  = Column(Integer)
    joindate = Column(Time)

    def __repr__(self):
        return "<Account(username='%s')>" % (self.username)
    

class Character(Base):
    __tablename__ = 'character'
    id = Column(Integer, primary_key = True)
    account_id = Column(Integer, ForeignKey('account.id'))
    
