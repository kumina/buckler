# Buckler: a proxy for adding authentication and authorization to Kibana

Buckler is an authentication frontend for ELK (Elasticsearch, Logstash,
Kibana).  It behaves like a proxy, allowing only access to those indexes the
logged in user.

Buckler is implemented as a Django app. You will need a Django project to
configure and run the application. A sample (buildout based) Django project is
available in the kumina/buckler-project repository at Github.

## How does it work?

Buckler provides a view that serves as the main entry point for accessing
Kibana.  All requests are forwarded to either Kibana or directly to
Elasticsearch (in cases where Kibana will not properly handle the request, e.g.
when access configuration indexes).

Buckler provides a very simple authentication mechanism. It does not define any
models.

Buckler will inject some additional JavaScript code to add a logout button and
(optionally) hide certain configuration options.

Lastly, Buckler will attempt to set up an initial index based on the
configuration after first login.

## Configuration

Buckler expects the following Django applications ettings:

- `KIBANA_UPSTREAM`: The URL where Kibana can be found.
  E.g. `http://localhost:5601` - no trailing slash!
- `ES_UPSTREAM`: The URL where Elasticsearch can be found.
  E.g. `http://localhost:9200` - no trailing slash!
- `ES_USERDATA_PREFIX`: the Elasticsearch index prefix for storing user
  data. E.g. `.kibana`
- `CONFIG`: A dictionary keyed by usernames that have access. Each value
  consists of a dictionary holding hashed password (using
  `crypt.crypt()`), the indexes the user has access to (as a tuple), and
  the index used to store the user's preferences. For example:

```
CONFIG = {
	'john': {
		'password': '$6$....',
		'indexes': ('logstash-john-\*', 'logstash-company-\*'),
		'userdata_index': 'john',
	},
	'demo': {
		'password': '$6$....',
		'indexes': ('logstash-demo-\*',)
		'userdata_index': 'demo',
	}
}
```

Buckler can (and will) set up initial indexes based on the 'indexes' property.
However, if you use time stamp based indexes (e.g. [logstash-]YYYY.MM.DD),
set these explicitly as 'autoindexes' if you want these to be created instead.
For example:

`{'john': {..., 'autoindexes': ('[logstash-john-]YYYY.MM.DD',) ..}`

Currently, only 'daily' interval is supported!

## Requirements

At this point, Buckler will only work with Kibana 4.1.x. It will not work with
newer versions (e.g. 4.3) since the protocol has changed significantly.

Buckler has been tested with Django 1.4 and 1.8 on Python 2.7.

## Running tests

You can test this package using 'tox'. Install it in a virtualenv if you don't
already have it:

```
virtualenv .; bin/pip install tox
bin/tox
```

## Credits

Buckler was initially developed by Ivo van der Wijk (m3r consultancy B.V.)
under commission from Kumina b.v.
