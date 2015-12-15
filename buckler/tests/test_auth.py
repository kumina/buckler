import responses
import json

from django.test import TestCase
from django.test import Client
from django.core.urlresolvers import reverse

from mock import patch

# test auth: redirect naar login url,
# logout


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
        with self.settings(CONFIG={'john': {'password': 's3cr3t'}}):
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
        fake_login(c, 'blah')
        with self.settings(CONFIG={'john': {'password': 's3cr3t'}}):
            response = c.get('/')
            # there's not much to test against, entire response will be mock
            # data
            self.assertNotEquals(response.status_code, 302)

    @patch("requests.post")
    def test_auth_post(self, r):
        c = Client()
        fake_login(c, 'blah')
        with self.settings(CONFIG={'john': {'password': 's3cr3t'}}):
            response = c.post('/')
            self.assertNotEquals(response.status_code, 200)
            # there's not much to test against, entire response will be mock
            # data
            self.assertNotEquals(response.status_code, 302)


class TestInjectView(TestCase):
    def test_normal(self):
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': 's3cr3t'}}):
            response = c.get(reverse('injectjs'))
        self.assertEquals(response.context.get('username'), 'john')
        self.assertEquals(response.context.get('logout'), reverse('logout'))
        self.assertFalse(response.context.get('poweruser'))

    def test_poweruser(self):
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': 's3cr3t',
                                            'poweruser': True}}):
            response = c.get(reverse('injectjs'))
        self.assertEquals(response.context.get('username'), 'john')
        self.assertEquals(response.context.get('logout'), reverse('logout'))
        self.assertTrue(response.context.get('poweruser'))

    @responses.activate
    def test_injections(self):
        responses.add(responses.GET, 'http://testing.test:124/',
                      body='<html><body>Hello</body></html',
                      status=200)
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': 's3cr3t',
                                            'poweruser': True}}):
            response = c.get('/')
        self.assertInHTML('<script src="{0}"></script>'
                        .format(reverse('injectjs')), response.content)


class TestIndexAccess(TestCase):
    """ verify a logged in user has only access to specific indexes """

    @responses.activate
    def test_config_index_rewrite(self):
        responses.add(responses.GET, 'http://testing.test:124/config',
                      body=json.dumps({'kibana_index': '.kibana'}),
                      status=200, content_type="application/json")
        c = Client()
        fake_login(c, 'john')
        with self.settings(CONFIG={'john': {'password': 's3cr3t',
                                            'poweruser': True}}):
            response = c.get('/config')

        data = json.loads(response.content)
        self.assertEquals(data.get('kibana_index'), '.kibana-john')
