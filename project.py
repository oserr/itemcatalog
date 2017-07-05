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
    return flask_session.get(cookie)


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
        return 'The username cannot be empty. Try again.'
    password = request.form['password']
    if not password:
        return 'The password cannot be empty. Try again.'
    user = session.query(User).get(username)
    if not user:
        return ('A user with name {} does not exist. Try again.'
            .format(username))
    salt = gensalt()
    hsh = get_hash(user.salt, password)
    if hsh != user.pwdhsh:
        return 'The password is incorrect. Try again.'
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
        return 'The username cannot be empty. Try again.'
    password = request.form['password']
    if not password:
        return 'The password cannot be empty. Try again.'
    user = session.query(User).get(username)
    if user:
        return 'The username is already taken. Try again.'
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
        return 'You need to log in to create an item.'
    categories = session.query(Category).all()
    if request.method == 'GET':
        return render_template('newitem.html', categories=categories)
    title = request.form.get('title')
    if not title:
        return 'The item must have a name. Try again.'
    title = title.lower()
    description = request.form.get('description')
    if not description:
        return 'The item must have a description. Try again.'
    cat = request.form.get('category')
    if cat == 'other':
        cat = request.form.get('newcategory')
        if not cat:
            return 'New category name must be something. Try again.'
        cat = cat.lower()
        if cat == 'other':
            return 'New catogory name cannot be other. Try again.'
        category = (session.query(Category)
            .filter(Category.name == cat).first())
        if category:
            return 'Category {} already exist. Try again.'.format(cat)
        category = Category(name=cat)
        session.add(category)
        session.commit()
    else:
        category = (session.query(Category)
            .filter(Category.name == cat).first())
        if not category:
            return 'Category {} does not exist. Try again.'.format(cat)
        item = session.query(Item).filter(Item.name == title).first()
        if item and item.category == category:
            return ('Item {} already exists for category {}. Try again.'
                .format(title, category.name))
    user = session.query(User).get(flask_session['username'])
    item = Item(name=title,
        description=description,
        category_name=cat,
        category=category,
        user_email=user.email,
        user=user)
    session.add(item)
    session.commit()
    return redirect('/')


@app.route('/item/<int:item_id>')
def getitem(item_id):
    item = session.query(Item).get(item_id)
    if not item:
        return 'Item not found. Try again.'
    return render_template('item.html',
        email=get_session_email('username'), item=item)


@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
def edit_item(item_id):
    email = get_session_email('username')
    if not email:
        return 'Must be logged in to edit an item'
    item = session.query(Item).get(item_id)
    if not item:
        return 'Item not found. Try again.'
    user = session.query(User).get(email)
    if not user:
        return 'Must create account to be able to edit items.'
    if item.user != user:
        return 'To edit, user must own item'
    if request.method == 'GET':
        categories = (session.query(Category)
            .filter(Category.name != item.category_name).all())
        return render_template('newitem.html',
            item=item, categories=categories, email=email)
    title = request.form.get('title')
    if not title:
        return 'The item must have a name. Try again.'
    title = title.lower()
    description = request.form.get('description')
    if not description:
        return 'The item must have a description. Try again.'
    cat = request.form.get('category')
    if cat == 'other':
        cat = request.form.get('newcategory')
        if not cat:
            return 'New category name must be something. Try again.'
        cat = cat.lower()
        if cat == 'other':
            return 'New catogory name cannot be other. Try again.'
        category = (session.query(Category)
            .filter(Category.name == cat).first())
        if category:
            return 'Category {} already exist. Try again.'.format(cat)
        category = Category(name=cat)
        session.add(category)
        session.commit()
    else:
        category = (session.query(Category)
            .filter(Category.name == cat).first())
        if not category:
            return 'Category {} does not exist. Try again.'.format(cat)
        existing_item = session.query(Item).filter(Item.name == title).first()
        if existing_item and existing_item.category == category:
            return ('Item {} already exists for category {}. Try again.'
                .format(title, category.name))
    user = session.query(User).get(flask_session['username'])
    is_cat_different = False
    if item.category_name != cat:
        is_cat_different = True
        old_cat_name = item.category_name
    if item.name != title or item.description != description \
        or item.category_name != cat:
        item.name = title
        item.description = description
        item.category_name = cat
        item.category = category
        session.add(item)
        session.commit()
    if is_cat_different:
        cat_count = (session.query(Item)
            .filter(Item.category_name == old_cat_name).count())
        if not cat_count:
            (session.query(Category)
                .filter(Category.name == old_cat_name).delete())
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
    cat_count = session.query(Item).filter(Item.category_name == cat).count()
    if not cat_count:
        session.query(Category) .filter(Category.name == cat).delete()
    return redirect('/')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
