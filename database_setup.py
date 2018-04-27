import os
import sys
from datetime import datetime
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

#Class
class Publication(Base):
    #Mapper
    __tablename__ = 'publication'
    #Table
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)

#Class
class Book(Base):
    #Mapper
    __tablename__ = 'book'
    #Table
    id = Column(Integer, primary_key=True)
    title = Column(String(500), nullable=False, index=True)
    author = Column(String(350))
    avg_rating = Column(String(20))
    format = Column(String(50))
    image = Column(String(100), unique=True)
    num_pages = Column(Integer)
    pub_date = Column(String(20))
    pub_id = Column(Integer, ForeignKey('publication.id'))

#Class
class User(Base):
    #Mapper
    __tablename__= 'users'
    #Table
    id = Column(Integer, primary_key=True)
    user_name = Column(String(30))
    user_email = Column(String(60), unique=True, index=True)
    user_password = Column(String(80))
    registration_date = Column(String(20), nullable=False, default=datetime.now())

engine = create_engine('sqlite:///bookcatalogue.db')

Base.metadata.create_all(engine)
