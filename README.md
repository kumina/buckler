# Buckler

Buckler is an authentication frontend for ELK (ElasticSearch, Logstash, Kibana).
It behaves like a proxy, allowing only access to those indexes the logged in
user.

Buckler is implemented as a Django app. You will need a Django project to
configure and run the application. A sample (buildout based) Django project
is availeble (URL yet to be published)

## How does it work?

Buckler provides a view that serves as the main entry point for accessing
Kibana.
All requests are forwarded to either Kibana or directly to ElastiSearch (in
cases where Kibana will not properly handle the request, e.g. when access
configuration indexes)

Buckler provides a very simple authentication mechanism. It does not define
any models.

Buckler will inject some additional javascript code to add a logout button and
(optionally) hide certain configuration options

Lastly, Buckler will attempt to setup an initial index based on the
configuration after first login.

## Configuration


## Requirements

At this point, Buckler will only work with Kibana 4.1.x. It will not work with
newer versions (e.g. 4.3) since the protocol has changed significantly.

Buckler has been tested with Django 1.8 on python 2.7

## Credits

Buckler was developed by Ivo van der Wijk (m3r consultancy B.V.). Development
has been sponsored by Kumina (www.kumina.nl)
