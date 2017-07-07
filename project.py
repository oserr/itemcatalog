#!/usr/bin/env python
# project.py
import hmac
import string
import random
from flask import (Flask, render_template,
                   request, redirect, url_for, flash,
                   send_from_directory)
from flask import session as flask_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import User, Category, Item, Base


def gensalt(length=16):
    """Generate a random salt value for a password.

    :param length
        The lenght of the salt value, with default value of 16.
    :return
        A string containing a randomly generated salt value composed of
        alphanumeric characters.
    """
    if not length or length < 0:
        raise ValueError('The salt length must be a positive integer')
    alnum = string.ascii_letters + string.digits
    return ''.join(random.choice(alnum) for _ in range(length))


def get_hash(salt, psswd):
    """Create a hash from a salt and password.

    :param salt
        The salt value. Cannot be empty.
    :param psswd
        The password value. Cannot be empty.
    :return
        A hash value of the salt and password.
    """
    if not salt or not psswd:
        raise ValueError('The salt and password cannot be empty')
    return hmac.new(salt.encode(), psswd.encode()).hexdigest()


def get_session_email(cookie):
    '''Return the email associated with the session or None if request is not
    part of session.

    :param cookie
        The name of the cookie for the email
    '''
    return flask_session.get(cookie)


def get_category_count(category):
    '''Return the number of items that are part of a given category.'''
    return session.query(Item).filter(Item.category_name == category).count()


def delete_category(category):
    '''Deletes a category from the database.'''
    session.query(Category) .filter(Category.name == category).delete()


class ItemFields:
    '''A helper class to create or update Items.

    Contains everything, except user information, necessary to initialize
    an Item.
    '''
    def __init__(self, name, description, category_name, category):
        '''Initialize an ItemField.'''
        self.name = name
        self.description = description
        self.category_name = category_name
        self.category = category

    def create_item(self, user):
        '''Create an item from these item fields for a given user.'''
        if not user:
            raise ValueError('User cannot be null')
        if not self.category:
            self.create_category()
        item = Item(name=self.name,
            description=self.description,
            category_name=self.category_name,
            category=self.category,
            user_email=user.email,
            user=user)
        session.add(item)
        session.commit()

    def update_item(self, item):
        '''Update an item if any of the fields have changed.'''
        if not user:
            raise ValueError('User cannot be null')
        if item.category_name != self.category_name and not category:
            self.create_category()
        if item.name != self.name or item.description != self.description \
            or item.category_name != self.category_name:
            item.name = self.name
            item.description = self.description
            item.category_name = self.category_name
            item.category = self.category
            session.add(item)
            session.commit()

    def create_category(self):
        '''Creates a new category and sets its category field.'''
        self.category = Category(name=self.category_name)
        session.add(self.category)
        session.commit()


class AppErr(Exception):
    '''An exception for all application errors.'''
    pass


def get_item_fields():
    '''Gets the fields from a form to edit or create an item.

    :return
        An ItemFields with the values to create or update an Item. If the user
        is also creating a new category, then ItemField.category will contain
        the new category, otherwise it is None,
    '''
    title = request.form.get('title')
    if not title:
        raise AppErr('The item must have a name.')
    title = title.lower()
    description = request.form.get('description')
    if not description:
        raise AppErr('The item must have a description.')
    cat_name = request.form.get('category')
    category = None
    if not cat_name:
        raise AppErr('The item must have a category')
    cat_name = cat_name.lower()
    if cat_name == 'other':
        cat_name = request.form.get('newcategory')
        if not cat_name:
            raise AppErr('New category name must be something.')
        cat_name = cat_name.lower()
        if cat_name == 'other':
            raise AppErr('New catogory name cannot be other.')
        if get_category_count(cat_name):
            raise AppErr('Category {} already exist.'.format(cat_name))
    else:
        category = session.query(Category) \
            .filter(Category.name == cat_name).first()
        if not category:
            raise AppErr('Category {} does not exist.'.format(cat_name))
        item = session.query(Item).filter(Item.name == title).first()
        if item and item.category == category:
            raise AppErr('Item {} already exists for category {}.' \
                .format(title, category.name))
    return ItemFields(title, description, cat_name, category)


engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__, static_url_path='')

@app.route('/')
@app.route('/items')
def index():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('index.html',
        email=get_session_email('username'),
        categories=categories, items=items)


@app.route('/logout')
def logout():
    flask_session.pop('username', None)
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_session_email('username'):
        return redirect('/')
    if request.method == 'GET':
        return send_from_directory('html', 'login.html')
    username = request.form['user']
    if not username:
        raise AppErr('The username cannot be empty.')
    password = request.form['password']
    if not password:
        raise AppErr('The password cannot be empty.')
    user = session.query(User).get(username)
    if not user:
        raise AppErr('A user with name {} does not exist.'.format(username))
    salt = gensalt()
    hsh = get_hash(user.salt, password)
    if hsh != user.pwdhsh:
        raise AppErr('The password is incorrect.')
    flask_session['username'] = username
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_session_email('username'):
        return redirect('/')
    if request.method == 'GET':
        return send_from_directory('html', 'register.html')
    username = request.form['user']
    if not username:
        raise AppErr('The username cannot be empty.')
    password = request.form['password']
    if not password:
        raise AppErr('The password cannot be empty.')
    user = session.query(User).get(username)
    if user:
        raise AppErr('The username is already taken.')
    salt = gensalt()
    hsh = get_hash(salt, password)
    user = User(email=username, salt=salt, pwdhsh=hsh)
    session.add(user)
    session.commit()
    flask_session['username'] = username
    return redirect('/')


@app.route('/newitem', methods=['GET', 'POST'])
def newitem():
    if not get_session_email('username'):
        raise AppErr('You need to log in to create an item.')
    categories = session.query(Category).all()
    if request.method == 'GET':
        return render_template('newitem.html', categories=categories)
    item_fields = get_item_fields()
    user = session.query(User).get(flask_session['username'])
    item_fields.create_item(user)
    return redirect('/')


@app.route('/item/<int:item_id>')
def getitem(item_id):
    item = session.query(Item).get(item_id)
    if not item:
        raise AppErr('Item not found.')
    return render_template('item.html',
        email=get_session_email('username'), item=item)


@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
def edit_item(item_id):
    email = get_session_email('username')
    if not email:
        raise AppErr('Must be logged in to edit an item')
    item = session.query(Item).get(item_id)
    if not item:
        raise AppErr('Item not found.')
    user = session.query(User).get(email)
    if not user:
        raise AppErr('Must create account to be able to edit items.')
    if item.user != user:
        raise AppErr('To edit, user must own item')
    if request.method == 'GET':
        categories = (session.query(Category)
            .filter(Category.name != item.category_name).all())
        return render_template('newitem.html',
            item=item, categories=categories, email=email)
    item_fields = get_item_fields()
    item_fields.update_item(item)
    return redirect('/')


@app.route('/item/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(item_id):
    email = get_session_email('username')
    if not email:
        return 'Must be logged in to delete an item'
    item = session.query(Item).get(item_id)
    if not item:
        return 'Item not found. Try again.'
    user = session.query(User).get(email)
    if not user:
        return 'Must create account to be able to edit items.'
    if item.user != user:
        return 'To delete, user must own item'
    if request.method == 'GET':
        return render_template('item_delete.html', item=item)
    cat = item.category_name
    session.query(Item).filter(Item.id == item.id).delete()
    if not get_category_count(cat):
        delete_category(cat)
    return redirect('/')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
