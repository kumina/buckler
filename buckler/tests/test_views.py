import responses
import json
import urlparse

from django.conf import settings

from django.test import TestCase, override_settings
from django.test import Client
from django.test import RequestFactory
from django.core.urlresolvers import reverse
from django.http import Http404

from mock import Mock, patch

from ..views import get_full_url


def fake_login(client, username):
    session = client.session
    session['username'] = username
    session.save()
    return session


class TestAuthenticationViews(TestCase):

    def test_get_unauthenticated(self):
        c = Client()
        response = c.get(reverse('login'))
        self.assertTrue('buckler/login.html' in
                        [t.name for t in response.templates])

    def test_login_fail(self):
        c = Client()
        with self.settings(CONFIG={}):
            response = c.post(reverse('login'),
                              {"username": 'john',
                               "password": 's3cr3t'})
            self.assertTrue('buckler/login.html' in
                            [t.name for t in response.templates])
            self.assertTrue('error' in response.context)

    @patch("requests.post")
    def test_login_success(self, r):
        c = Client()
        with self.settings(CONFIG={
            'john': {'password': 'AA2QILwUzOYBM', 'userdata_index': 'foo'}
        }):
            response = c.post(reverse('login'),
                              {"username": 'john',
                               "password": 's3cr3t'})
            self.assertFalse(response.context and 'error' in response.context)
            self.assertEquals(response.status_code, 302)
            self.assertEquals(c.session.get('username', None), 'john')

    def test_logout(self):
        c = Client()
        fake_login(c, 'blah')
        response = c.get(reverse('logout'))
        self.assertEquals(c.session.get('username', 'empty'), 'empty')
        self.assertEquals(response.status_code, 302)

    def test_unauth_get(self):
        c = Client()
        response = c.get('/')
        self.assertRedirects(response, reverse('login'))

    def test_unauth_post(self):
        c = Client()
        response = c.post('/')
        self.assertRedirects(response, reverse('login'))

    @patch("requests.get")
    def test_auth_get(self, r):
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': '$1$....',
                                            'userdata_index': 'foo'}}):
            response = c.get('/')
            # there's not much to test against, entire response will be mock
            # data
            self.assertNotEquals(response.status_code, 302)

    @patch("requests.post")
    def test_auth_post(self, r):
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': '$1$....',
                                            'userdata_index': 'foo'}}):
            response = c.post('/')
            self.assertNotEquals(response.status_code, 200)
            # there's not much to test against, entire response will be mock
            # data
            self.assertNotEquals(response.status_code, 302)


class TestInjectView(TestCase):
    def test_normal(self):
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': '$1$....',
                                            'userdata_index': 'foo'}}):
            response = c.get(reverse('injectjs'))
        self.assertEquals(response.context.get('username'), 'john')
        self.assertEquals(response.context.get('logout'), reverse('logout'))

    @responses.activate
    def test_injections(self):
        responses.add(responses.GET, 'http://testing.test:124/',
                      body='<html><body>Hello</body></html',
                      status=200)
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': '$1$....',
                                            'userdata_index': 'foo'}}):
            response = c.get('/')
        self.assertInHTML('<script src="{0}"></script>'
                        .format(reverse('injectjs')), response.content)


class TestKibanaIndexAccess(TestCase):
    """ Test kibana config rewrite """

    @responses.activate
    def test_config_index_rewrite(self):
        responses.add(responses.GET, 'http://testing.test:124/config',
                      body=json.dumps({'kibana_index': '.kibana'}),
                      status=200, content_type="application/json")
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': '$1$....',
                                            'userdata_index': 'foo'}}):
            response = c.get('/config')

        data = json.loads(response.content)
        self.assertEquals(data.get('kibana_index'), '.kibana-foo')


class TestIndexAccess(TestCase):
    """ verify a logged in user has only access to specific indexes """
    def setUp(self):
        self.factory = RequestFactory()

    def assertURL(self, url, host, base, data={}):
        """ assert a URL match on host/path/data """
        parts = urlparse.urlparse(url)
        self.assertEquals("{0}://{1}".format(parts.scheme, parts.netloc), host)
        self.assertEquals(parts.path, base)
        params = dict(urlparse.parse_qsl(parts.query))
        if data:
            self.assertEquals(params, data)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'userdata_index': 'foo'}})
    def test_kibana_proxy(self):
        """ a non-elastic request should go to kibana """
        path = 'bla/foo'
        data = {'this': '1', 'that': '2'}
        request = self.factory.get(path, data)
        request.session = {'username': 'john'}
        res = get_full_url('bla/foo', request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path, data)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'userdata_index': 'foo'}})
    def test_kibana_usermatch(self):
        """ A user can access his own kibana index which gets proxied
            directly to ES"""
        path = 'elasticsearch/.kibana-foo'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.ES_UPSTREAM, '/.kibana-foo')

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'userdata_index': 'foo'}})
    def test_kibana_usermismatch(self):
        """ A user cannot access any other kibana config index """
        path = 'elasticsearch/.kibana-jane'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        self.assertRaises(Http404, lambda: get_full_url(path, request))

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'userdata_index': 'foo'}})
    def test_es_nodes(self):
        """ calls to /elasticsearch/_nodes go verbatim to Kibana """
        path = 'elasticsearch/_nodes'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/elasticsearch/_nodes')

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'userdata_index': 'foo'}})
    def test_es_root(self):
        """ calls to /elasticsearch/ go verbatim to Kibana"""
        path = 'elasticsearch/'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/elasticsearch/')

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'userdata_index': 'foo'}})
    def test_cluster_allowed_kibanaindex(self):
        """ /elasticsearch/_cluster only for allowed indexes """
        path = 'elasticsearch/_cluster/.kibana-foo'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_cluster_allowed(self):
        """ /elasticsearch/_cluster only for allowed indexes """
        path = 'elasticsearch/_cluster/logstash-john-123'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',
                                                    'logstash-test-*'),
                                        'userdata_index': 'foo'}})
    def test_elasticsearch_all(self):
        """" A request for /elasticsearch/_all should be rewritten
             to the explicitly allowed indexes in stead """
        path = 'elasticsearch/_all'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM,
                       '/elasticsearch/logstash-john-*,logstash-test-*/_all')

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',
                                                    'logstash-test-*'),
                                        'userdata_index': 'foo'}})
    def test_elasticsearch_query(self):
        """" A request for /elasticsearch/_query should be rewritten
             to the explicitly allowed indexes in stead """
        path = 'elasticsearch/_query'
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM,
                       '/elasticsearch/logstash-john-*,logstash-test-*/_query')

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_mget_allowed(self):
        """ test _mget which takes indexes in the body """
        path = 'elasticsearch/_mget'
        request = self.factory.post(path, content_type="application/json",
                                    data=json.dumps({
                                        'docs': [{'_index': 'logstash-john-123'}]
                                    }))
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_mget_disallowed(self):
        """ test _mget which takes indexes in the body """
        path = 'elasticsearch/_mget'
        request = self.factory.post(path, content_type="application/json",
                                    data=json.dumps({
                                        'docs': [{'_index': 'logstash-jane-123'}]
                                    }))
        request.session = {'username': 'john'}
        self.assertRaises(Http404, lambda: get_full_url(path, request))

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_mget_extended_allowed(self):
        """ test _mget which takes indexes in the body """
        path = 'elasticsearch/logstash-john-1/_mget'
        request = self.factory.post(path, content_type="application/json",
                                    data=json.dumps({
                                        'docs': [{'_index': 'logstash-john-123'}]
                                    }))
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_mget_extended_disallowed(self):
        """ test _mget which takes indexes in the body """
        path = 'elasticsearch/logstash-jane-1/_mget'
        request = self.factory.post(path, content_type="application/json",
                                    data=json.dumps({
                                        'docs': [{'_index': 'logstash-jane-123'}]
                                    }))
        request.session = {'username': 'john'}
        self.assertRaises(Http404, lambda: get_full_url(path, request))

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_msearch_allowed(self):
        """ test _msearch which takes indexes in the body """
        path = 'elasticsearch/_msearch'
        body = "\n".join([json.dumps({'somerandom': 'json'}),
                          json.dumps({'index': ["logstash-john-123",
                                                "logstash-john-234"]}),
                          json.dumps({'index': "logstash-john-333"})])
        request = self.factory.post(path, content_type="application/json",
                                    data=body)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_msearch_disallowed(self):
        """ test _msearch which takes indexes in the body """
        path = 'elasticsearch/_msearch'
        # body has an index (jane) that john doesn't have access to
        body = "\n".join([json.dumps({'somerandom': 'json'}),
                          json.dumps({'index': ["logstash-john-123",
                                                "logstash-jane-234"]}),
                          json.dumps({'index': "logstash-john-333"})])
        request = self.factory.post(path, content_type="application/json",
                                    data=body)
        request.session = {'username': 'john'}
        self.assertRaises(Http404, lambda: get_full_url(path, request))

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_msearch_extended_allowed(self):
        """ test _msearch which takes indexes in the body with
            index in path as well """
        path = 'elasticsearch/logstash-john-666/_msearch'
        body = "\n".join([json.dumps({'somerandom': 'json'}),
                          json.dumps({'index': ["logstash-john-123",
                                                "logstash-john-234"]}),
                          json.dumps({'index': "logstash-john-333"})])
        request = self.factory.post(path, content_type="application/json",
                                    data=body)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_msearch_extended_disallowed(self):
        """ test _msearch which takes indexes in the body with
            index in path as well """
        path = 'elasticsearch/logstash-jane-666/_msearch'
        # body has an index (jane) that john doesn't have access to
        body = "\n".join([json.dumps({'somerandom': 'json'}),
                          json.dumps({'index': ["logstash-john-123",
                                                "logstash-john-234"]}),
                          json.dumps({'index': "logstash-john-333"})])
        request = self.factory.post(path, content_type="application/json",
                                    data=body)
        request.session = {'username': 'john'}
        self.assertRaises(Http404, lambda: get_full_url(path, request))

    @override_settings(CONFIG={'john': {'password': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_index_direct_allowed(self):
        """ just /elasticsearch/someindex,someotherindex """
        path = "elasticsearch/logstash-john-1,logstash-john-2"
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        res = get_full_url(path, request)
        self.assertURL(res, settings.KIBANA_UPSTREAM, '/' + path)

    @override_settings(CONFIG={'john': {'passVword': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    def test_index_direct_disallowed(self):
        """ just /elasticsearch/someindex,someotherindex """
        path = "elasticsearch/logstash-john-1,logstash-jane-2"
        request = self.factory.get(path)
        request.session = {'username': 'john'}
        self.assertRaises(Http404, lambda: get_full_url(path, request))


class TestIndexCreateion(TestCase):
    @override_settings(CONFIG={'john': {'passVword': '$1$....',
                                        'indexes': ('logstash-john-*',),
                                        'userdata_index': 'foo'}})
    @patch("buckler.views.create_index_patterns")
    def test_trigger(self, cip):
        """ """
        c = Client()
        fake_login(c, 'john')
        with patch("requests.post", return_value=Mock(status_code=201,
                    content='',
                    headers={'content-type': 'application/json'},
                    META={})):
            c.post('/elasticsearch/.kibana-foo/config/')

        self.assertEquals(cip.call_count, 1)

    @responses.activate
    def test_indexes_created(self):
        from ..views import create_index_patterns
        request = Mock(body=json.dumps({}), META={})
        base = settings.ES_UPSTREAM + '/.kibana-foo/'

        responses.add(responses.PUT,
                      base + '_mapping/index-pattern',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + 'index-pattern/logstash-john-*?op_type=create',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + '_refresh',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + 'index-pattern/logstash-john-*',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + 'config/4.1.2/_update',
                      body='',
                      status=200)
        create_index_patterns("/elasticsearch/.kibana-foo/config/4.1.2",
                              username="john",
                              config={'indexes': ('logstash-john-*',),
                                      'userdata_index': 'foo'},
                              request=request)

        self.assertEquals(json.loads(responses.calls[4].request.body),
                          {"doc": {"defaultIndex": "logstash-john-*"}})

    @responses.activate
    def test_timestamp_indexes_created(self):
        from ..views import create_index_patterns
        request = Mock(body=json.dumps({}), META={})
        base = settings.ES_UPSTREAM + '/.kibana-foo/'

        responses.add(responses.PUT,
                      base + '_mapping/index-pattern',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + 'index-pattern/[logstash-john-]YYYY.MM.DD?op_type=create',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + '_refresh',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + 'index-pattern/[logstash-john-]YYYY.MM.DD',
                      body='',
                      status=200)
        responses.add(responses.POST,
                      base + 'config/4.1.2/_update',
                      body='',
                      status=200)
        create_index_patterns("/elasticsearch/.kibana-foo/config/4.1.2",
                              username="john",
                              config={'indexes': ('logstash-john-*',),
                                      'autoindexes':
                                      ('[logstash-john-]YYYY.MM.DD',),
                                      'userdata_index': 'foo'},
                              request=request)

        self.assertEquals(json.loads(responses.calls[4].request.body),
                          {"doc": {"defaultIndex": "[logstash-john-]YYYY.MM.DD"}})
