from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import models

engine     = create_engine('postgresql://postgres:ltybcxtge@localhost:5432/pywow')

db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))



#for init-reinit database.
def drop_db():
        models.Base.metadata.drop_all(bind=engine)

def init_db():
        models.Base.metadata.create_all(bind=engine)

def insert_default_realms():
        #[(name, )]
        realms = [(0,
                   0,
                   0,
                   'PyWoW',
                   9,)]

        for realm in realms:
                r =  models.Realm()
                r.type     = realm[0]
                r.isLocked = realm[1]
                r.color    = realm[2]
                r.name     = realm[3]
                r.timezone = realm[4]
                db_session.add(r)
                
        db_session.commit()
        
def insert_default_accounts():
        #[(login,pwHash, gmlevel)]
        accs = [('ADMINISTRATOR', 'a34b29541b87b7e4823683ce6c7bf6ae68beaaac', 3),
                ('GAMEMASTER'   , '7841e21831d7c6bc0b57fbe7151eb82bd65ea1f9', 2),
                ('MODERATOR'    , 'a7f5fbff0b4eec2d6b6e78e38e8312e64d700008', 1),
                ('PLAYER'       , '3ce8a96d17c5ae88a30681024e86279f1a38c041', 0)]
        
        for acc in accs:
                ac = models.Account()
                ac.username = acc[0]
                ac.pwHash   = acc[1]
                ac.gmlevel  = acc[2]
                db_session.add(ac)
                
        db_session.commit()
        
if __name__ == '__main__':
        drop_db()
        init_db()
        insert_default_realms()
        insert_default_accounts()
