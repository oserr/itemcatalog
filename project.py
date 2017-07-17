#!/usr/bin/env python
# project.py
import functools
import json
import hmac
import string
import random
from oauth2client import client as auth_client
from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import send_from_directory
from flask import session as flask_session
from flask import g
from flask import make_response
from flask.json import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import User, Category, Item, Base


def gensalt(length=16):
    '''Generate a random salt value for a password.

    :param length
        The lenght of the salt value, with default value of 16.
    :return
        A string containing a randomly generated salt value composed of
        alphanumeric characters.
    '''
    if not length or length < 0:
        raise ValueError('The salt length must be a positive integer')
    alnum = string.ascii_letters + string.digits
    return ''.join(random.choice(alnum) for _ in range(length))


def get_hash(salt, psswd):
    '''Create a hash from a salt and password.

    :param salt
        The salt value. Cannot be empty.
    :param psswd
        The password value. Cannot be empty.
    :return
        A hash value of the salt and password.
    '''
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


AUTH_ERR_MSG = 'Coult not verify your access level for %s. You have to log in.'
ACCT_ERR_MSG = 'Could not find your account. You have to create an account.'

def requires_auth(func):
    '''Returns a decorator function that verifies a user is logged in.'''
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        email = get_session_email(SESSION_COOKIE)
        if not email:
            err = AUTH_ERR_MSG % request.base_url
            html = render_template('err.html', err=err)
            response = make_response(html, 401)
            response.headers['WWW-Authenticate'] = \
                'Basic realm="Login Required"'
            return response
        user = session.query(User).get(email)
        if not user:
            html = render_template('err.html', err=ACCT_ERR_MSG)
            response = make_response(html, 401)
            response.headers['WWW-Authenticate'] = \
                'Basic realm="Account Required"'
            return response
        g.user = user
        return func(*args, **kwargs)
    return decorated


def json_requires_auth(func):
    '''Returns a decorator function that verifies a user is logged in for
    requests made via json API.
    '''
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        email = get_session_email(SESSION_COOKIE)
        if not email:
            err = AUTH_ERR_MSG % request.base_url
            response = gen_error_msg(err)
            response.status_code = 401
            response.headers['WWW-Authenticate'] = \
                'Basic realm="Login Required"'
            return response
        user = session.query(User).get(email)
        if not user:
            response = gen_error_msg(ACCT_ERR_MSG)
            response.status_code = 401
            response.headers['WWW-Authenticate'] = \
                'Basic realm="Account Required"'
            return response
        g.user = user
        return func(*args, **kwargs)
    return decorated


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
        session.refresh(item)
        return item

    def update_item(self, item):
        '''Update an item if any of the fields have changed.'''
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
        return item

    def create_category(self):
        '''Creates a new category and sets its category field.'''
        self.category = Category(name=self.category_name)
        session.add(self.category)
        session.commit()


class AppErr(Exception):
    '''An exception for all application errors.'''
    pass


def get_item_fields(data, create_mode=True):
    '''Gets the fields from a dictionary to create a new Item.

    Extracts the title, description, and category name to create or update
    an Item.

    :param data
        A dictionary containing the fields.
    :return
        An ItemFields with the values to create or update an Item.
    '''
    if not data:
        raise AppErr('Missing fields data')
    title = data.get('title')
    if not title:
        raise AppErr('The item must have a name.')
    title = title.lower()
    description = data.get('description')
    if not description:
        raise AppErr('The item must have a description.')
    cat_name = data.get('category')
    category = None
    if not cat_name:
        raise AppErr('The item must have a category')
    cat_name = cat_name.lower()
    if cat_name == 'other':
        cat_name = data.get('newcategory')
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
        if create_mode and item and item.category == category:
            raise AppErr('Item {} already exists for category {}.' \
                .format(title, category.name))
    return ItemFields(title, description, cat_name, category)


def gen_error_msg(msg):
    '''Return a json response with a failure message.'''
    return jsonify({'success': False, 'error': msg})


# Create and setup the DB
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create the Flask application
app = Flask(__name__, static_url_path='')

# Global variables/definitions
SESSION_COOKIE='email'
SUCCESS_JSON = {'success': True}
CLIENT_ID = json.loads(open('client_secret.json').read())['web']['client_id']

@app.route('/')
@app.route('/items')
def index():
    '''Renders the categories and items on the home page.'''
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('index.html',
        email=get_session_email(SESSION_COOKIE),
        categories=categories, items=items)


@app.route('/json')
@app.route('/json/items')
def json_index():
    '''Returns the categories and items in json format.'''
    categories = [cat.to_dict() for cat in session.query(Category).all()]
    items = [item.to_dict() for item in session.query(Item).all()]
    response_dict = {'categories': categories, 'items': items}
    return jsonify(response_dict)


@app.route('/items/<int:category_id>')
def get_category_items(category_id):
    '''Renders the items associated with a given category.'''
    category = session.query(Category).get(category_id)
    if not category:
        raise AppErr('Category not found.')
    items = session.query(Item).filter(Item.category == category).all()
    return render_template('index.html',
        email=get_session_email(SESSION_COOKIE),
        categories=[category], items=items)


@app.route('/json/items/<int:category_id>')
def json_get_category_items(category_id):
    '''Returns the items associated with a given category in json format.'''
    category = session.query(Category).get(category_id)
    if not category:
        raise AppErr('Category not found.')
    items = [item.to_dict() for item in \
        session.query(Item).filter(Item.category == category).all()]
    return jsonify({'categories': [category.to_dict()], 'items': items})


@app.route('/logout')
def logout():
    '''Logs out a user by removing the cookie associated with a session.

    If a user is not logged in then nothing happens. User is redirected to
    main page.
    '''
    flask_session.pop(SESSION_COOKIE, None)
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Logs in a user by creating a session cookie and redirects user to home
    page.
    '''
    if get_session_email(SESSION_COOKIE):
        return redirect('/')
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form['email']
    if not email:
        raise AppErr('The email cannot be empty.')
    password = request.form['password']
    if not password:
        raise AppErr('The password cannot be empty.')
    user = session.query(User).get(email)
    if not user:
        raise AppErr('A user with email {} does not exist.'.format(email))
    salt = gensalt()
    hsh = get_hash(user.salt, password)
    if hsh != user.pwdhsh:
        raise AppErr('The password is incorrect.')
    flask_session[SESSION_COOKIE] = email
    return redirect('/')


@app.route('/json/login', methods=['POST'])
def json_login():
    '''JSON API endpoint to login a user.

    The client must set the Content-Type header to application/json, otherwise
    get_json() returns None. The request must contain an email and password
    fields, e.g., {email: "john@gmail.com", password: "password"}, both of
    which are strings.

    :return
        A json object of the form {success: bool}, where success is true if
        the user was able to get logged in, or false otherwise. If success
        is false, then json object will contain a string field, error, with
        a description of the error, e.g.,
        { success: false, error: "email does not exist"}. If the login is
        successful, then the HTTP response will contain a cookie which
        the client must send in subsequent requests.
    '''
    if get_session_email(SESSION_COOKIE):
        return jsonify(SUCCESS_JSON)
    data = request.get_json()
    if not data:
        return gen_error_msg('Bad request or ill-formed json')
    email = data.get('email')
    if not email:
        return gen_error_msg('Cannot login without email')
    password = data.get('password')
    if not password:
        return gen_error_msg('Cannot login without password')
    user = session.query(User).get(email)
    if not user:
        return gen_error_msg('Do not recognize email')
    hsh = get_hash(user.salt, password)
    if hsh != user.pwdhsh:
        return gen_error_msg('The password is incorrect.')
    flask_session[SESSION_COOKIE] = email
    return jsonify(SUCCESS_JSON)


@app.route('/glogin', methods=['POST'])
def glogin():
    '''Logs in a user via google signin.'''
    if get_session_email(SESSION_COOKIE):
        return redirect('/')
    token = request.form['token']
    id_info = auth_client.verify_id_token(token, CLIENT_ID)
    if id_info['iss'] not in ('accounts.google.com',
        'https://accounts.google.com'):
        raise AppErr('Credentials from Google are not right')
    email = id_info['email']
    user = session.query(User).get(email)
    if not user:
        raise AppErr('User {} does not have an account'.format(email))
    flask_session[SESSION_COOKIE] = email
    # TODO: send error responses in json so onerrer or status != 200
    # can do something
    return ''


@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Creates a record for a new user and redirects user to the main page.'''
    if get_session_email(SESSION_COOKIE):
        return redirect('/')
    if request.method == 'GET':
        return send_from_directory('html', 'register.html')
    email = request.form['email']
    if not email:
        raise AppErr('The email cannot be empty.')
    password = request.form['password']
    if not password:
        raise AppErr('The password cannot be empty.')
    user = session.query(User).get(email)
    if user:
        raise AppErr('The email is already taken.')
    salt = gensalt()
    hsh = get_hash(salt, password)
    user = User(email=email, salt=salt, pwdhsh=hsh)
    session.add(user)
    session.commit()
    flask_session[SESSION_COOKIE] = email
    return redirect('/')


@app.route('/json/register', methods=['POST'])
def json_register():
    '''JSON API endpoint to register a user.

    The client must set the Content-Type header to application/json, otherwise
    get_json() returns None. The request must contain an email and password
    fields, e.g., {email: "john@gmail.com", password: "password"}, both of
    which are strings.

    :return
        A json object of the form {success: bool}, where success is true if
        the user was able to register, or false otherwise. If success
        is false, then json object will contain a string field, error, with
        a description of the error, e.g.,
        { success: false, error: "email already exist"}. If the registration
        is successful, then the HTTP response will contain a cookie which
        the client must send in subsequent requests that require a user to
        be logged in.
    '''
    if get_session_email(SESSION_COOKIE):
        return jsonify(SUCCESS_JSON)
    data = request.get_json()
    if not data:
        return gen_error_msg('Bad request or ill-formed json')
    email = data.get('email')
    if not email:
        return gen_error_msg('Cannot register without an email')
    password = data.get('password')
    if not password:
        return gen_error_msg('Cannot register without a password')
    user = session.query(User).get(email)
    if user:
        return gen_error_msg('An account already exists for this email')
    salt = gensalt()
    hsh = get_hash(salt, password)
    user = User(email=email, salt=salt, pwdhsh=hsh)
    session.add(user)
    session.commit()
    flask_session[SESSION_COOKIE] = email
    return jsonify(SUCCESS_JSON)


@app.route('/newitem', methods=['GET', 'POST'])
@requires_auth
def newitem():
    '''Lets a user a create a new item for a given category.'''
    categories = session.query(Category).all()
    if request.method == 'GET':
        return render_template('newitem.html', categories=categories)
    item_fields = get_item_fields(request.form)
    item_fields.create_item(g.user)
    return redirect('/')


@app.route('/json/newitem', methods=['POST'])
@json_requires_auth
def json_newitem():
    '''API endpoint for creating a new item.

    Before creating an item, a user must log in to obtain a session cookie,
    which should be included in the request Cookie header. The json request
    must contain the following fields: title, description, and category.
    Optionally, if the user is creating a new category, then the category
    field must be set to other and the newcategory field must contain the new
    category name. On success, the success field will be set to true and the
    item field will contain the new item. On failure, the success field will be
    set to false and the error field will contain a description of the error.
    '''
    try:
        item_fields = get_item_fields(request.get_json())
    except AppErr as err:
        return gen_error_msg(str(err))
    item = item_fields.create_item(g.user)
    return jsonify({'success': True, 'item': item.to_dict()})


@app.route('/item/<int:item_id>')
def getitem(item_id):
    '''Renders a specific item.'''
    item = session.query(Item).get(item_id)
    if not item:
        raise AppErr('Item not found.')
    return render_template('item.html',
        email=get_session_email(SESSION_COOKIE), item=item)


@app.route('/json/item/<int:item_id>')
def json_getitem(item_id):
    '''Returns the data for a given item in json format.'''
    item = session.query(Item).get(item_id)
    if not item:
        raise AppErr('Item not found.')
    return jsonify({'item': item.to_dict()})


@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
@requires_auth
def edit_item(item_id):
    '''Allows a user who owns an item to edit its data.

    The user must own, and be logged in, to be able to edit an item. Everything
    about an item can be changed, except the item ID, which is used internally
    by the server. If an item is updated successfully, then user is redirected
    to main page.
    '''
    item = session.query(Item).get(item_id)
    if not item:
        raise AppErr('Item not found.')
    if item.user != g.user:
        raise AppErr('To edit, user must own item')
    if request.method == 'GET':
        categories = (session.query(Category)
            .filter(Category.name != item.category_name).all())
        return render_template('newitem.html',
            item=item, categories=categories, email=email)
    item_fields = get_item_fields(request.form, create_mode=False)
    item_fields.update_item(item)
    return redirect('/')


@app.route('/json/edit', methods=['POST'])
def json_edit_item():
    '''API endpoint for users to edit items.

    A user must own an item, and must be logged in, to be able to modify it.
    The JSON request must contain the following fields: item_id, title,
    description, and category. Optionally, if category is other, then it must
    also contain newcategory. On failure, success is set to false and error
    contains a failure description. On success, the success field is set to
    true and the item is embedded in the response. Not that a request that
    does not modify the item is treated like a success.
    '''
    email = get_session_email(SESSION_COOKIE)
    if not email:
        return gen_error_msg('Must be logged in to edit an item')
    data = request.get_json()
    item_id = data.get('item_id')
    if not item_id:
        return gen_error_msg('Must provide the id of the item to update')
    item = session.query(Item).get(item_id)
    if not item:
        return gen_error_msg('Item with id {} not found'.format(item_id))
    user = session.query(User).get(email)
    if not user:
        return gen_error_msg('Must create account to be able to edit items')
    if item.user != user:
        return gen_error_msg('To edit, user must own item')
    try:
        item_fields = get_item_fields(data, create_mode=False)
    except AppErr as err:
        return gen_error_msg(str(err))
    item_fields.update_item(item)
    return jsonify({'success': True, 'item': item.to_dict()})


@app.route('/item/<int:item_id>/delete', methods=['GET', 'POST'])
def delete_item(item_id):
    '''Allows a user a who owns an item to delete the item.'''
    email = get_session_email(SESSION_COOKIE)
    if not email:
        raise AppErr('Must be logged in to delete an item.')
    item = session.query(Item).get(item_id)
    if not item:
        raise AppErr('Item not found.')
    user = session.query(User).get(email)
    if not user:
        raise AppErr('Must create account to be able to edit items.')
    if item.user != user:
        raise AppErr('To delete, user must own item')
    if request.method == 'GET':
        return render_template('item_delete.html', item=item)
    cat = item.category_name
    session.query(Item).filter(Item.id == item.id).delete()
    if not get_category_count(cat):
        delete_category(cat)
    return redirect('/')


@app.route('/json/delete', methods=['POST'])
def json_delete_item():
    '''API endpoint to delete an item.

    Before creating an item, a user must log in to obtain a session cookie,
    which should be included in the request Cookie header. The json request
    must contain the ID of the item in field item_id. On success, the success
    field will be set to true. On failure, the success field will be set to
    false and the error field will contain a description of the error.
    '''
    email = get_session_email(SESSION_COOKIE)
    if not email:
        return gen_error_msg('Must be logged in to delete an item')
    data = request.get_json()
    item_id = data.get('item_id')
    if not item_id:
        return gen_error_msg('Cannot delete item without item ID')
    item = session.query(Item).get(item_id)
    if not item:
        return gen_error_msg('Item not found')
    user = session.query(User).get(email)
    if not user:
        return gen_error_msg('Must create account to be able to edit items')
    if item.user != user:
        return gen_error_msg('To delete, user must own item')
    cat = item.category_name
    session.query(Item).filter(Item.id == item.id).delete()
    if not get_category_count(cat):
        delete_category(cat)
    return jsonify(SUCCESS_JSON)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
