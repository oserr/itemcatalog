# ItemCatalog

A basic [Flask][1] web app with a database backend that allows users to create basic profiles
and then create categories with items. The point of the application is not to be interesting,
but rather to excercise web development with an SQL database.

## Prerequisites

* [Python][2]
* Any browser, to test the app.
* [Anaconda/conda][3]. This is not strictly needed, but recommended, because `conda`, a
  package, dependency, and environment manger, will allow you to easily recreate my development
  environment.

## Setup the environment

Assuming that you have `conda`, run the following

```bash
cd thisRepoDir
conda upgrade conda
conda-env create conda-env.txt
```

## Run the app

```bash
cd thisRepoDir
python project.py
```

This should launch the application on _localhost_ port 5000, and should produce the following
output

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
