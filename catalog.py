from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import make_response, flash
from flask import session as login_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import SingletonThreadPool

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from database_setup import Base, User, Category, Item

import httplib2
import json
import requests
import random
import string

CLIENTID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db', poolclass=SingletonThreadPool)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLoginState():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Unauthorised.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain the authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Validate the access token
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Validate that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENTID:
        response = make_response(
            json.dumps("Client ID does not match"), 401)
        print "Token's client ID does not match app"
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in session info
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['user_name'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    print data['email']
    if session.query(User).filter_by(email=data['email']).count() != 0:
        current_user = session.query(User).filter_by(email=data['email']).one()
    else:
        newUser = User(name=data['name'],
                       email=data['email'])
        session.add(newUser)
        session.commit()
        current_user = newUser

    login_session['user_id'] = current_user.id
    print current_user.id

    output = ''
    output += '<h2>Welcome, '
    output += login_session['user_name']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' "style = "width: 200px; height: 200px;border-radius: 100px;">'
    flash("logged in as %s" % login_session['user_name'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('User not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' %
    login_session['access_token']
    h = httplib2.Http()
    result = \
        h.request(uri=url, method='POST', body=None,
                  headers={'content-type':
                           'application/x-www-form-urlencoded'})[0]

    print url
    print 'Result : '
    print result
    if result['status'] == '200':
        del login_session['user_id']
        del login_session['email']
        del login_session['picture']
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['user_name']

        response = make_response(json.dumps('Disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Successfully logged out")
        return redirect('/category')
        # return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/category/')
def showCategory():
    """Show all Categories"""
    categories = session.query(Category).all()
    return render_template('category.html', categories=categories)


@app.route('/category/add/', methods=['GET', 'POST'])
def addCategory():
    """Add Category"""
    # check logged-in state
    if 'user_name' not in login_session:
        return redirect('/login')

    user_id = login_session['user_id']

    if request.method == 'POST':
        addCategory = Category(name=request.form['name'], user_id=user_id)
        session.add(addCategory)
        flash('New Category %s Successfully Created' % addCategory.name)
        session.commit()
        return redirect(url_for('showCategory'))
    else:
        return render_template('category_add.html')


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """Delete a Category"""
    # check logged-in state
    if 'user_name' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()

    if category.user_id != login_session['user_id']:
        flash('Category cannot be deleted by current user')
        return redirect(url_for('showCategory'))

    if request.method == 'POST':
        session.delete(category)
        session.commit()

        flash('%s Deleted Successfully' % category.name)

        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('category_delete.html', category=category)


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    """Edit a Category"""
    # check logged-in state
    if 'user_name' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(id=category_id).one()

    if category.user_id != login_session['user_id']:
        flash('Category cannot be edited by current user')
        return redirect(url_for('showCategory'))

    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            flash('Category edited successfully %s' % category.name)
            return redirect(url_for('showCategory'))
    else:
        return render_template('category_edit.html', category=category)


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/item/')
def showItem(category_id):
    """Show all the Items"""
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return render_template('item.html', items=items, category=category)


@app.route('/category/<int:category_id>/item/add', methods=['GET', 'POST'])
def addItem(category_id):
    """Add new Item"""
    if 'user_name' not in login_session:
        return redirect('/login')

    user_id = login_session['user_id']

    if request.method == 'POST':
        addItem = Item(name=request.form['name'],
                       category_id=category_id,
                       description=request.form['description'],
                       user_id=user_id)
        session.add(addItem)
        session.commit()
        flash('%s Successfully Created' % (addItem.name))
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('item_add.html', category_id=category_id)

    return render_template('item_add.html', category_id=category_id)


@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    """Delete a particular Item"""
    if 'user_name' not in login_session:
        return redirect('/login')

    item = session.query(Item).filter_by(id=item_id).one()

    if item.user_id != login_session['user_id']:
        flash('Item cannot be deleted by current user')
        return redirect(url_for('showItem', category_id=category_id))

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('%s Successfully Deleted' % (item.name))
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('item_delete.html',
                               category_id=category_id,
                               item=item)


@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    """Edit a particular item"""
    if 'user_name' not in login_session:
        return redirect('/login')

    item = session.query(Item).filter_by(id=item_id).one()

    if item.user_id != login_session['user_id']:
        flash('Item cannot be edited by current user')
        return redirect(url_for('showItem', category_id=category_id))

    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('%s Successfully Updated' % (item.name))
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('item_edit.html',
                               category_id=category_id,
                               item_id=item_id,
                               item=item)


@app.route('/category/JSON')
def categoriesJSON():
    """Return JSON for all the categories"""
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/category/<int:category_id>/JSON')
def categoryJSON(category_id):
    """Return JSON of all the items for a particular category"""
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/item/JSON')
def itemsJSON():
    """Return JSON for a particular item"""
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    """Return JSON for a particular item of a particular category"""
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item=item.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
