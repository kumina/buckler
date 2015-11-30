import requests
import fnmatch
from urlparse import urljoin
import json

from django.http import HttpResponse
from django.views.generic import View
from django.shortcuts import render, redirect
from django.http import Http404
from django.core.urlresolvers import reverse

from django.conf import settings


def get_session(request):
    username = request.session.get('username')

    if username:
        return username, settings.CONFIG.get(username)
    return None, None


def open_indexes(config):
    indexes = ",".join(config.get('indexes', []))
    requests.post(urljoin(settings.ES_UPSTREAM, indexes + '/_open'))


def create_index_patterns(url, username, config, request):

    version = url.rsplit('/', 1)[-1]
    orig_conf = json.loads(request.body)
    # url = elasticsearch/.kibana-test1/config/4.1.1

    indexes = config['indexes']
    indexbase = settings.ES_UPSTREAM + '/.kibana-{0}'.format(username)

    for index in indexes:
        requests.put(indexbase + '/_mapping/index-pattern', data=json.dumps(
                    {"index-pattern": {"properties":
                     {"title": {"type": "string"}, "timeFieldName":
                    {"type": "string"}, "intervalName": {"type": "string"},
                     "fields": {"type": "string"},
                     "fieldFormatMap": {"type": "string"}}}}))
        requests.post(indexbase + '/index-pattern/{0}?op_type=create'.format(index),
                      data=json.dumps({'title': index,
                                       'timeFieldName': '@timestamp'}))
        requests.post(indexbase + '/_refresh')
        requests.post(indexbase + '/index-pattern/{0}'.format(index),
                      data=json.dumps({"title":index,"timeFieldName":"@timestamp","fields":"[{\"name\":\"_index\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":false,\"analyzed\":false,\"doc_values\":false},{\"name\":\"_type\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"geoip.location\",\"type\":\"geo_point\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"@version\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"_source\",\"type\":\"_source\",\"count\":0,\"scripted\":false,\"indexed\":false,\"analyzed\":false,\"doc_values\":false},{\"name\":\"_id\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":false,\"analyzed\":false,\"doc_values\":false},{\"name\":\"request\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"agent\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"referrer.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"auth\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"ident\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"timestamp.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"response.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"clientip\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"host\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"bytes.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"timestamp\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"ident.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"clientip.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"host.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"verb\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"message\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"auth.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"referrer\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"httpversion.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"request.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"@timestamp\",\"type\":\"date\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"agent.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false},{\"name\":\"bytes\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"response\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"httpversion\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":true,\"doc_values\":false},{\"name\":\"verb.raw\",\"type\":\"string\",\"count\":0,\"scripted\":false,\"indexed\":true,\"analyzed\":false,\"doc_values\":false}]"}))
    orig_conf['defaultIndex'] = indexes[0]
    requests.post(indexbase + '/config/{0}/_update'.format(version),
                  data=json.dumps({"doc": orig_conf}))



class LoginView(View):
    def get(self, request, *args, **kwargs):
        return render(request, "kibanana/login.html")

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username in settings.CONFIG and \
           settings.CONFIG[username]['password'] == password:
            request.session['username'] = username
            open_indexes(settings.CONFIG[username])
            # indexes may not be ready at this point yet. Alternatively,
            # redirect to a url that checks the state of indexes and
            # keeps redirecting, possibly with a delay in the served html
            return redirect('/')  # redirect sw that checks + opens indexes?
        else:
            return render(request, "kibanana/login.html",
                          {'error': 'Invalid username or password'})


class InjectJSView(View):
    def get(self, request, *args, **kwargs):
        username, config = get_session(request)
        ctx = dict(username=username, logout=reverse("logout"),
                   poweruser=config.get('poweruser'))

        return render(request, 'kibanana/inject.js', ctx,
                      content_type="application/javascript")


class LogoutView(View):
    def get(self, request, *args, **kwargs):
        del request.session['username']
        return redirect('/')


class BananaView(View):

    def get_full_url(self, url, request):
        """
            Construct the full (upstream) url
        """
        upstream = settings.KIBANA_UPSTREAM
        username, config = get_session(self.request)

        body = request.body

        parts = url.split('/')

        def index_allowed(index):
            """ Verify if access to the index is allowed by
                any of the config indexes """
            if index == ".kibana-" + username:
                return True

            for allowed_index in config['indexes']:
                if fnmatch.fnmatch(index, allowed_index):
                    return True
            return False

        def check_explicit_index(part):
            """ If there's an index in 'part' where the user does not have
                access to, raise 404 """

            indexes = part.split(",")
            for index in indexes:
                if not index_allowed(index):
                    raise Http404("Access to index denied: {0}".format(index))

        def check_mget_body():
            data = json.loads(body)
            for doc in data.get('docs', []):
                index = doc.get('_index')
                if index:
                    if not index_allowed(index):
                        raise Http404("Access to index denied: {0}"
                                      .format(index))

        def check_msearch_body():
            # Not very efficient - possibly multiple lines containing
            # (possibly) multiple indexes (e.g. for an entire year or
            # longer) match against multiple allowed_index patterns
            for line in body.splitlines():
                data = json.loads(line)
                if 'index' in data:
                    indexes = data.get('index')
                    if not isinstance(indexes, list):
                        indexes = [indexes]
                    for index in indexes:
                        if not index_allowed(index):
                            raise Http404("Access to index denied: {0}"
                                          .format(index))

        if parts[0].lower() == 'elasticsearch' and len(parts) > 1:
            # /elasticsearch/ and /elasticsearch/_nodes
            if parts[1] in ('', '_nodes'):
                pass  # allowed
            # /elasticsearch/_cluster/health/.kibana-<user>
            elif parts[1] == '_cluster':
                check_explicit_index(parts[-1])
            # /elasticsearch/.kibana-someuser
            elif parts[1].startswith(".kibana"):
                # bypass kibana, go directly to ES since kibana will not allow
                # us to access any other .kibana index than the configured one
                upstream = settings.ES_UPSTREAM
                url = url.split('/', 1)[1]
            # /elasticsearch/_all or /elasticsearch/_query
            elif parts[1] in ('_all', '_query'):
                # include .kibana-<username> ?
                parts[1] = ",".join(config['indexes']) + "/" + parts[1]
                url = "/".join(parts)
            # /elasticsearch/_mget
            elif parts[1] == '_mget':
                check_mget_body()

            # /elasticsearch/index/_mget
            elif len(parts) > 2 and parts[2] == '_mget':
                check_explicit_index(parts[1])
                check_mget_body()
            # /elasticsearch/_msearch
            elif parts[1] == '_msearch':
                check_msearch_body()
            # /elasticsearch/index/_msearch
            elif len(parts) > 2 and parts[2] == '_msearch':
                check_explicit_index(parts[1])
                check_msearch_body()
            # /elasticsearch/index/_somemethod_or_type
            else:
                check_explicit_index(parts[1])

        param_str = self.request.GET.urlencode()
        request_url = u'%s/%s' % (upstream, url)
        request_url += '?%s' % param_str if param_str else ''
        # print "RESULT", request_url
        return request_url

    def dispatch(self, *args, **kwargs):
        if not get_session(self.request)[0]:
            return redirect('login')

        return super(BananaView, self).dispatch(*args, **kwargs)

    def get(self, request, url, *args, **kwargs):
        username, config = get_session(request)

        request_url = self.get_full_url(url, request)

        res = requests.get(request_url)

        data = res.content

        if url == "config":
            data_decode = json.loads(data)
            data_decode['kibana_index'] = ".kibana-{0}".format(username)
            data = json.dumps(data_decode)

        if url == '':  # / requested: inject javascript
            data = data.replace("</body>",
                                '<script src="/inject.js"></script></body>')

        return HttpResponse(data, status=res.status_code,
                            content_type=res.headers['content-type'])

    def post(self, request, url, *args, **kwargs):
        username, config = get_session(request)

        request_url = self.get_full_url(url, request)

        res = requests.post(request_url, data=request.body)

        if url.startswith("elasticsearch/.kibana-{0}/config/"
                          .format(username)) and res.status_code == 201:
            create_index_patterns(url, username, config, request)

        return HttpResponse(res.content, status=res.status_code,
                            content_type=res.headers['content-type'])

    def head(self, request, url, *args, **kwargs):
        # print "HEAD called!", request, url
        return self.get(request, url, *args, **kwargs)

    def delete(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url, request)

        res = requests.delete(request_url, data=request.body)
        return HttpResponse(res.content, status=res.status_code,
                            content_type=res.headers['content-type'])

    def put(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url, request)

        res = requests.put(request_url, data=request.body)
        return HttpResponse(res.content, status=res.status_code,
                            content_type=res.headers['content-type'])
