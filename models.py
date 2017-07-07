# models.py

from sqlalchemy import (Column, ForeignKey, Integer, String)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    email = Column(String(50), primary_key=True)
    salt = Column(String(16), nullable=False)
    pwdhsh = Column(String(100), nullable=False)


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)

    def to_dict(self):
        '''Return this Category in dictionary format.'''
        return {'id': self.id, 'name': self.name}


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    description = Column(String(400), nullable=False)
    category_name = Column(String(250), ForeignKey('category.name'))
    category = relationship(Category)
    user_email = Column(String(75), ForeignKey('user.email'))
    user = relationship(User)


engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
