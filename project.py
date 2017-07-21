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


def login_helper(data):
    '''Checks the login data provided in a form or in a JSON object.

    :param data
        A dictionary containing the login credentials in the following fields:
        - email
        - password
    :return
        The user data from the DB.
    '''
    if not data:
        raise AppErr('Did not find any data in the request')
    email = data.get('email')
    if not email:
        raise AppErr('Cannot login without email')
    password = data.get('password')
    if not password:
        raise AppErr('Cannot login without password')
    user = session.query(User).get(email)
    if not user:
        raise AppErr('Do not recognize email')
    hsh = get_hash(user.salt, password)
    if hsh != user.pwdhsh:
        raise AppErr('The password is incorrect.')
    return user


def register_helper(data):
    '''Checks the user registration data provided in a form or in a JSON
    object and creates a user profile.

    :param data
        A dictionary containing the login credentials in the following fields:
        - email
        - password
    '''
    if not data:
        raise AppErr('Did not find any data in the request')
    email = data.get('email')
    if not email:
        raise AppErr('Cannot register without email')
    password = data.get('password')
    if not password:
        raise AppErr('Cannot register without password')
    user = session.query(User).get(email)
    if user:
        raise AppErr('User already exists')
    salt = gensalt()
    hsh = get_hash(salt, password)
    user = User(email=email, salt=salt, pwdhsh=hsh)
    session.add(user)
    session.commit()
    flask_session[SESSION_COOKIE] = email


def make_html_err(err):
    '''Render the html error page.

    :param err
        The error message.
    :return
        A string representing the HTML page.
    '''
    return render_template('err.html', err=err)


def make_json_err(msg):
    '''Creates a json error object.

    :param msg
        The error message
    :return
        A json object with the following fields
        - success: true or false
        - error: the error message
    '''
    return jsonify({'success': False, 'error': msg})


AUTH_ERR_MSG = 'Coult not verify your access level for %s. You have to log in.'
ACCT_ERR_MSG = 'Could not find your account. You have to create an account.'

def requires_auth(err_func):
    '''Decorator function to pass in argument to decorated function.

    :param err_func
        A function that creates json or html error objects.
    '''
    def wrapper(func):
        '''Creates a decorated function.

        :param func
            The decorated function
        '''
        @functools.wraps(func)
        def decorated(*args, **kwargs):
            '''Enforces that a user exists and is logged in.

            If a user is logged in, then we add the user to the application
            context, otherwise we send back a 401 response.
            '''
            email = get_session_email(SESSION_COOKIE)
            if not email:
                content = err_func(AUTH_ERR_MSG % request.base_url)
                response = make_response(content, 401)
                response.headers['WWW-Authenticate'] = \
                    'Basic realm="Login Required"'
                return response
            user = session.query(User).get(email)
            if not user:
                content = err_func(ACCT_ERR_MSG)
                response = make_response(content, 401)
                response.headers['WWW-Authenticate'] = \
                    'Basic realm="Account Required"'
                return response
            g.user = user
            return func(*args, **kwargs)
        return decorated
    return wrapper


ITEM_NOT_FOUND_ERR = 'Sorry, but we could not find item with ID %d'
OWNER_ERR = 'Sorry, but you cannot modify %s'

def requires_item_owner(err_func):
    '''Decorator function to pass in argument to decorated function.

    :param err_func
        A function that creates json or html error objects.
    '''
    def wrapper(func):
        '''Creates a decorated function.

        :param func
            The decorated function
        '''
        @functools.wraps(func)
        def decorated(*args, **kwargs):
            '''Enforces that a user owns an item before calling the decorated
            function.

            This function relies on requires_auth authenticating a user and
            defining g.user, and hence should be closer than requires_auth to
            the function being decorated.
            '''
            item_id = kwargs['item_id']
            item = session.query(Item).get(item_id)
            if not item:
                content = err_func(ITEM_NOT_FOUND_ERR % item_id)
                return make_response(content, 404)
            if g.user != item.user:
                content = err_func(OWNER_ERR % item.name)
                return make_response(content, 403)
            g.item = item
            return func(*args, **kwargs)
        return decorated
    return wrapper


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
    '''Allows a user to get all the items.'''
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('index.html',
        email=get_session_email(SESSION_COOKIE),
        categories=categories, items=items)


@app.route('/json')
@app.route('/json/items')
def json_index():
    '''Allows a user to get all the items via the JSON API endpoint.

    :return
        A JSON object containing the following fields:
        - success: True or false, depending on success of operation.
        - categories: An array category objects, only present on success.
        - items: An array of items in the catalog, only present on success.
        - error: An error message, only present if success is false.
    '''
    categories = [cat.to_dict() for cat in session.query(Category).all()]
    items = [item.to_dict() for item in session.query(Item).all()]
    response_dict = {'success': True, 'categories': categories, 'items': items}
    return jsonify(response_dict)


@app.route('/items/<int:category_id>')
def get_category_items(category_id):
    '''Allows a user to get the items with a given category.'''
    category = session.query(Category).get(category_id)
    if not category:
        raise AppErr('Category not found.')
    items = session.query(Item).filter(Item.category == category).all()
    return render_template('index.html',
        with_link=True,
        email=get_session_email(SESSION_COOKIE),
        categories=[category], items=items)


@app.route('/json/items/<int:category_id>')
def json_get_category_items(category_id):
    '''Allows the user to get the items with a given category via the JSON API
    endpoint.

    :return
        A JSON object containing the following fields:
        - success: True or false, depending on success of operation.
        - categories: An array of one element with the category object, only
          present on success.
        - items: An array of items with the same category, only present on
          success.
        - error: An error message, only present if success is false.
    '''
    category = session.query(Category).get(category_id)
    if not category:
        raise AppErr('Category not found.')
    items = [item.to_dict() for item in \
        session.query(Item).filter(Item.category == category).all()]
    return jsonify({
        'success': True,
        'categories': [category.to_dict()],
        'items': items
    })


@app.route('/logout')
def logout():
    '''Allows a user to log out.'''
    flask_session.pop(SESSION_COOKIE, None)
    return redirect('/')


@app.route('/login')
def get_login():
    '''Renders the form that allows a user to log in.'''
    if get_session_email(SESSION_COOKIE):
        return redirect('/')
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def post_login():
    '''Allows a user to log in.'''
    if get_session_email(SESSION_COOKIE):
        return redirect('/')
    user = login_helper(request.form)
    flask_session[SESSION_COOKIE] = user.email
    return redirect('/')


@app.route('/json/login', methods=['POST'])
def json_login():
    '''Allows a user to log in via the JSON API endpoint.

    The client must
    - set the Content-Type header to application/json
    - the request must contain a json object with the following fields:
        - email
        - password

    :return
        A JSON object with the following fields:
        - success: True or false, depending on success of operation.
        - error: An error message, only present if success is false.

        If login is successful, then session cookie is included in response.
    '''
    if get_session_email(SESSION_COOKIE):
        return jsonify(SUCCESS_JSON)
    user = login_helper(request.get_json())
    flask_session[SESSION_COOKIE] = user.email
    return jsonify(SUCCESS_JSON)


@app.route('/glogin', methods=['POST'])
def glogin():
    '''Allows a user to log in via google.'''
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
        raise AppErr('Do not recognize email')
    flask_session[SESSION_COOKIE] = email
    # TODO: send error responses in json so onerrer or status != 200
    # can do something
    return ''


@app.route('/register', methods=['POST'])
def register():
    '''Allows a user to register.'''
    if get_session_email(SESSION_COOKIE):
        return redirect('/')
    register_helper(request.form)
    return redirect('/')


@app.route('/json/register', methods=['POST'])
def json_register():
    '''Allows a user to get registered via the JSON API endpoint.

    The client must
    - set the Content-Type header to application/json
    - the request must contain a json object with the following fields:
        - email
        - password

    :return
        A JSON object with the following fields:
        - success: True or false, depending on success of operation.
        - item: The new item after being created, only present on success.
        - error: An error message, only present if success is false.

        If registration is successful, then session cookie is included in
        response.
    '''
    if get_session_email(SESSION_COOKIE):
        return jsonify(SUCCESS_JSON)
    register_helper(request.get_json())
    return jsonify(SUCCESS_JSON)


@app.route('/newitem', methods=['GET', 'POST'])
@requires_auth(make_html_err)
def newitem():
    '''Allows a user to create an item.'''
    if request.method == 'GET':
        categories = session.query(Category).all()
        return render_template('newitem.html', categories=categories)
    item_fields = get_item_fields(request.form)
    item_fields.create_item(g.user)
    return redirect('/')


@app.route('/json/newitem', methods=['POST'])
@requires_auth(make_json_err)
def json_newitem():
    '''Allows a user to create an item via the JSON API endpoint.

    Relies on requires_auth to authenticate the user.

    :return
        A JSON object with the following fields:
        - success: True or false, depending on success of operation.
        - item: The new item after being created, only present on success.
        - error: An error message, only present if success is false.
    '''
    try:
        item_fields = get_item_fields(request.get_json())
    except AppErr as err:
        return make_json_err(str(err))
    item = item_fields.create_item(g.user)
    return jsonify({'success': True, 'item': item.to_dict()})


@app.route('/item/<int:item_id>')
def getitem(item_id):
    '''Allows a user to get an item.'''
    item = session.query(Item).get(item_id)
    if not item:
        content = make_html_err(ITEM_NOT_FOUND_ERR % item_id)
        return make_response(content, 404)
    return render_template('item.html',
        email=get_session_email(SESSION_COOKIE), item=item)


@app.route('/json/item/<int:item_id>')
def json_getitem(item_id):
    '''Allows a user to get an item via the JSON API endpoint.

    :return
        A JSON object with the following fields:
        - success: True or false, depending on success of operatoin.
        - error: An error message, only present if success is false.
        - item: The item being fetched, only present on success.
    '''
    item = session.query(Item).get(item_id)
    if not item:
        content = make_json_err(ITEM_NOT_FOUND_ERR % item_id)
        return make_response(content, 404)
    return jsonify({'success': True, 'item': item.to_dict()})


@app.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
@requires_auth(make_html_err)
@requires_item_owner(make_html_err)
def edit_item(**kwargs):
    '''Allows a user to edit an item.

    edit_item depends on requires_auth to
    - authenticate user
    - load app context g with user
    and it depnds on requires_item_owner to
    - verify item exists
    - verify user owns item
    - load app context g with item

    :return
        A a Response object redirecting the user to the root page.
    '''
    if request.method == 'GET':
        categories = (session.query(Category)
            .filter(Category.name != g.item.category_name).all())
        return render_template('newitem.html',
            item=g.item, categories=categories, email=g.user.email)
    item_fields = get_item_fields(request.form, create_mode=False)
    item_fields.update_item(g.item)
    return redirect('/')


@app.route('/json/item/<int:item_id>/edit', methods=['POST'])
@requires_auth(make_json_err)
@requires_item_owner(make_json_err)
def json_edit_item(**kwargs):
    '''Allows a user to edit an item via the JSON API endpoint.

    json_edit_item depends on requires_auth to
    - authenticate user
    - load app context g with user
    and it depnds on requires_item_owner to
    - verify item exists
    - verify user owns item
    - load app context g with item

    :return
        A JSON object with the following fields:
        - success: True or false, depending on success of operatoin.
        - error: An error message, only present if success is false.
    '''
    data = request.get_json()
    try:
        item_fields = get_item_fields(data, create_mode=False)
    except AppErr as err:
        return make_json_err(str(err))
    item_fields.update_item(g.item)
    return jsonify({'success': True, 'item': g.item.to_dict()})


@app.route('/item/<int:item_id>/delete', methods=['GET', 'POST'])
@requires_auth(make_html_err)
@requires_item_owner(make_html_err)
def delete_item(**kwargs):
    '''Allows a user to delete an item.

    If, after deleting the item, there are no more items pointing to the
    deleted item's category, then the category is removed from the DB.

    json_edit_item depends on requires_auth to
    - authenticate user
    - load app context g with user
    and it depends on requires_item_owner to
    - verify item exists
    - verify user owns item
    - load app context g with item

    :return
        A a Response object redirecting the user to the root page.
    '''
    if request.method == 'GET':
        return render_template('item_delete.html', item=g.item)
    cat = g.item.category_name
    session.query(Item).filter(Item.id == g.item.id).delete()
    if not get_category_count(cat):
        delete_category(cat)
    return redirect('/')


@app.route('/json/item/<int:item_id>/delete', methods=['POST'])
@requires_auth(make_json_err)
@requires_item_owner(make_json_err)
def json_delete_item(**kwargs):
    '''Allows a user to delete an item via the JSON API endpoint.

    If, after deleting the item, there are no more items pointing to the
    deleted item's category, then the category is removed from the DB.

    json_edit_item depends on requires_auth to
    - authenticate user
    - load app context g with user
    and it depends on requires_item_owner to
    - verify item exists
    - verify user owns item
    - load app context g with item

    :return
        A JSON object with the following fields:
        - success: True or false, depending on success of operatoin.
        - error: An error message, only present if success is false.
    '''
    cat = g.item.category_name
    session.query(Item).filter(Item.id == g.item.id).delete()
    if not get_category_count(cat):
        delete_category(cat)
    return jsonify(SUCCESS_JSON)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
