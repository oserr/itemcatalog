# ItemCatalog

A basic [Flask][1] web app with a database backend that allows users to create basic profiles
and then create categories with items. The point of the application is to excercise web
development with an SQL database.

## Prerequisites

* [Python][2]
* Any browser, to test the app.
* [Anaconda/conda][3]. This is not strictly needed, but recommended, because `conda`, a
  package, dependency, and environment manger, will allow you to easily recreate my development
  environment, specified in `environment.yml`.
* An SQL database that can be used with [SQLAlchemy][alchemy].

## SQL database
Currently, the app is setup to use [PostgreSQL][postgres], but it can easily be modified to use
a different SQL database, as long as [SQLAlchemy][alchemy] supports it. If your database is already
in place, then it is simply a matter of [configuring the engine][engine]. For example, if you want
use [SQLite][sqlite], then all you need to do is replace

```python
engine = create_engine('postgresql://omar:omar@localhost:5432/catalog')
```

with something like

```python
engine = create_engine('sqlite:///itemcatalog.db')
```

If you want to use postgres, then you'll need to install it, create a user, and create a database,
unless you plan to use the app with the default user and database. If you are using Debian or one of
its derivatives, then you can install postgres by running

```bash
sudo apt-get update
sudo apt-get install postgresql
```

You can then create the user and database by running

```bash
createuser --createdb --pwprompt YourUserName  # You will be prompted for a password
createdb -O YourUserName YourDBName
```

where `YourUserName` is the username you want to use, and `YourDBName` is the name of the database.
Note, when you first install PostgresSQL, you may need to run the commands as user `postgres`, i.e.,

```bash
sudo -u postgres createuser --createdb --pwprompt YourUserName
sudo -u postgres createdb -O YourUserName YourDBName
```

Once you have everything setup, then you can modify the parameters used to create the SQLAlchemy engine,
for example, by replacing `omar:omar` with `YourUserName:YourPassowrd`, and replace `catalog` with
your database name.

## Setting up the environment

If you are using `conda`, then you can replicate my development envioronment for python by doing
the following

* make this directory your current working directory
* import the conda environment
    * to a global environment: `conda env create -n itemcatalog`.
    * locally for project: `conda env create -p env`.
* activate the environment
    * from global environment: `source activate itemcatalog`
    * from local environment: `source activate env`.
* to exit an enviornment, run `source deactivate`.

If you are on Windows, then you can ommit `source` from the `activate` and `deactivate` commands.

## Running the app

Activate the conda enviornment and run `python project.py`  to launch application. This should
launch the application on _localhost_ port 5000, and should produce the following output

```
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 219-374-909
```

## Play with the app

Once the application is running, you should be able to do any of the following

* Get the full list of items and categories.
* Create a basic user profile with an email and password.
* Create a new item or category.
* Edit an item.
* Delete an item.
* Any of the above via a JSON API endpoint. To access a JSON API endpoint, simply prepend the
  non-JSON URL path with `/json`. For example, if the URL is `localhost:5000/items`, then the
  path is `/items`, the JSON path would be `/json/items`, and the full URL would be
  `localhost:5000/json/items`.

## Source code

The meat of the application is located in _project.py_, except that the database models are
defined in _models.py_. The _templates_ directory contains the templates used by [Jinja2][4],
the default template engine used by [Flask][1], although the CSS file and Javascript files
located there are not proper templates, however, putting them there made my life simpler.
There's not a lot of Javascript, but there is enough to add a pinch of dynamism to the app.

## Improvements

The app needs more improvements than I can list here, but some important improvements are

* Support SSL/TLS to make the app more secure.
* Add a minimum password strength requirement.
* Enforce email registration requirement on JSON API endpoint.
* Create custom Google signin button so it can have the same style as other buttons.

[1]: http://flask.pocoo.org/
[2]: https://www.python.org/downloads/
[3]: https://www.continuum.io/downloads
[4]: http://jinja.pocoo.org/docs/2.9/
[alchemy]: https://www.sqlalchemy.org/
[postgres]: https://www.postgresql.org/
[engines]: http://docs.sqlalchemy.org/en/latest/core/engines.html
