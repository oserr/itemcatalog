#!/usr/bin/env python
# project.py
from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import User, Category, Item, Base

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)

@app.route('/')
@app.route('/items')
def index():
    is_session = False
    email = request.cookies.get('email')
    pwdhsh = request.cookies.get('secret')
    if email and pwdhsh:
        user = session.query(User).get(email)
        if pwdhsh == user.pwdhsh:
            is_session = True
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('index.html',
        is_session=is_session, categories=categories, items=items)


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
