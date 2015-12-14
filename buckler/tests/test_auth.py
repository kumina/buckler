import responses

from django.test import TestCase
from django.test import Client
from django.core.urlresolvers import reverse

from mock import patch

# test auth: redirect naar login url,
# logout


class TestAuthenticationViews(TestCase):
    def fake_login(self, client, username):
        session = client.session
        session['username'] = username
        session.save()
        return session

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
        self.fake_login(c, 'blah')
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
        self.fake_login(c, 'blah')
        with self.settings(CONFIG={'john': {'password': 's3cr3t'}}):
            response = c.get('/')
            # there's not much to test against, entire response will be mock
            # data
            self.assertNotEquals(response.status_code, 302)

    @patch("requests.post")
    def test_auth_post(self, r):
        c = Client()
        self.fake_login(c, 'blah')
        with self.settings(CONFIG={'john': {'password': 's3cr3t'}}):
            response = c.post('/')
            self.assertNotEquals(response.status_code, 200)
            # there's not much to test against, entire response will be mock
            # data
            self.assertNotEquals(response.status_code, 302)
