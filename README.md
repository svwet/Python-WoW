# Installation

Install git, download this repository and cd into repository folder.

Make sure that you have python3.4 in system.

Install python virtualenv, create virtual Python env and activate it. 

```bash
pip install virtualenv
virtualenv venv
. venv/bin/activate
```

or on Windows

```bash
pip.exe install virtualenv
virtualenv.exe venv
.\venv\Script\activate
```

Follow commands the same for Linux and Windows, the difference are "/" and "\" for paths and ".exe" postfix for Windows. 
Now you have local python virtualenv. It local for current project. Lets install dependencies:

```bash
pip install cryptography
pip install sqlalchemy
pip install psycopg2
```

# Setup

PyWoW use Postgresql. When this server was in development,  stable was a postgresql 9.4. Instance of postgresql should be installed and setted up.
In Server/database.py is line like

```python
engine     = create_engine('postgresql://postgres:ltybcxtge@localhost:5432/pywow')
```

String witch you see as argument of create_engine function is sqlalchemy connection string. Here is more about  http://docs.sqlalchemy.org/en/rel_1_0/core/engines.html .
Change "postgres" to your user, "ltybcxtge" to your password, "localhost" to host where you have your postgresql (or just leave as is :) and "pywow" is name of database to witch you want to connect realmserver.

After that type:

```bash
python Server/database.py
```
 
If all is ok, this action init (or reinit) database structure, and insert some default values. You can see raw database structure in Server/models.py.  

# Run

Next run the RealmServer.

```
python Server/RealmServer.py RealmServer.ini
```

If all network settings are ok, it should allow you to login under PLAYER@PLAYER.
Nothing else yet :)