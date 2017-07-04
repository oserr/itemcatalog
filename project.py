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


def get_session_status(cookie):
    return cookie in flask_session


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
    return render_template('index.html', is_session=get_session_status('username'),
        categories=categories, items=items)


@app.route('/logout')
def logout():
    flask_session.pop('username', None)
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_session_status('username'):
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
        return 'A user with name {} does not exist. Try again.'.format(username)
    salt = gensalt()
    hsh = get_hash(user.salt, password)
    if hsh != user.pwdhsh:
        return 'The password is incorrect. Try again.'
    flask_session['username'] = username
    return redirect('/')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_session_status('username'):
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
    if not get_session_status('username'):
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
        category = session.query(Category).get(cat)
        if category:
            return 'Category {} already exist. Try again.'.format(cat)
        category = Category(name=cat)
        session.add(category)
        session.commit()
    else:
        category = session.query(Category).get(cat)
        if not category:
            return 'Category {} does not exist. Try again.'.format(cat)
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


@app.route('/restaurants/<int:restaurant_id>/')
def restaurant_menu(restaurant_id):
    restaurant = session.query(Restaurant).get(restaurant_id)
    items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id)
    return render_template('menu.html', restaurant=restaurant, items=items)


@app.route('/new/item/<int:restaurant_id>/', methods=['GET', 'POST'])
def new_menu_item(restaurant_id):
    restaurant = session.query(Restaurant).get(restaurant_id)
    if not restaurant:
        return
    if request.method == 'GET':
        return render_template('new_menu_item.html', restaurant=restaurant)
    else:
        new_item = MenuItem(
            name=request.form['name'],
            restaurant=restaurant,
            description=request.form['description'],
            price=request.form['price'],
            course=request.form['course'])
        session.add(new_item)
        session.commit()
        flash('new menu item created')
        return redirect(url_for('restaurant_menu', restaurant_id=restaurant_id))


@app.route('/edit/menu/<int:restaurant_id>/<int:menu_id>', methods=['GET', 'POST'])
def edit_menu_item(restaurant_id, menu_id):
    restaurant = session.query(Restaurant).get(restaurant_id)
    menu = session.query(MenuItem).get(menu_id)
    if not restaurant or not menu or restaurant.id != menu.restaurant_id:
        return
    if request.method == 'GET':
        return render_template('edit_menu_item.html', restaurant=restaurant, menu=menu)
    else:
        if request.form['name'] != menu.name:
            menu.name = request.form['name']
            session.add(menu)
            session.commit()
        return redirect(url_for('restaurant_menu', restaurant_id=restaurant_id))


@app.route('/delete/menu/<int:restaurant_id>/<int:menu_id>')
def delete_menu_item(restaurant_id, menu_id):
    restaurant = session.query(Restaurant).get(restaurant_id)
    menu = session.query(MenuItem).get(menu_id)
    if restaurant and menu and restaurant.id == menu.restaurant_id:
        output = ''
        output += '<form action="/delete/menu/{}/{}" method="POST">'.format(restaurant_id, menu_id)
        output += '<p>Delete menu {} from restaurant {}</p>'.format(menu.name, restaurant.name)
        output += '<input type="submit" value="Delete">'
        output += '</form>'
        return output


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
