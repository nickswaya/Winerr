from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from app import db, app


with app.app_context():
    db.create_all()

engine = create_engine('sqlite:///database.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

# Set your classes here.


class User(Base):
    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(30))

    def __init__(self, username=None, password=None, email=None):
        self.username = username
        self.password = password
        self.email = email


class Transaction(Base):
    __tablename__ = 'Transactions'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=False, nullable=False)
    g_bucks = db.Column(db.Integer(), unique=False, nullable=False)
    price = db.Column(db.Float(), unique=False, nullable=False)

    def __init__(self, username=None, g_bucks=None, price=None):
        self.username = username
        self.g_bucks = g_bucks
        self.price = price



# Create tables.
Base.metadata.create_all(bind=engine)
