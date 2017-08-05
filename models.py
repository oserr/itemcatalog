# models.py

from sqlalchemy import (Column, ForeignKey, Integer, String)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user_acct'
    email = Column(String(50), primary_key=True)
    salt = Column(String(16), nullable=False)
    pwdhsh = Column(String(100), nullable=False)
    items = relationship('Item', backref=backref('user', lazy='joined'))


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    items = relationship('Item', backref=backref('category', lazy='joined'))

    def to_dict(self):
        '''Return this Category in dictionary format.'''
        return {'id': self.id, 'name': self.name}


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    description = Column(String(400), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    user_email = Column(String(75), ForeignKey('user_acct.email'))

    def to_dict(self):
        '''Return this Item in dictionary format.'''
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category_id': self.category_id
        }


engine = create_engine('postgresql://omar:omar@localhost:5432/catalog')
Base.metadata.create_all(engine)
