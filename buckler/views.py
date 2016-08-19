import crypt
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


def require_authentication(impl):
    """Decorator for redirecting to login when unauthenticated."""
    def wrapper(self, request, url, *args, **kwargs):
        if not get_session(request)[0]:
            return redirect('login')
        return impl(self, request, url, *args, **kwargs)
    return wrapper


def open_indexes(config):
    indexes = ",".join(config.get('indexes', []))
    requests.post(urljoin(settings.ES_UPSTREAM, indexes + '/_open'))


def field_config():
    return json.dumps([{u'analyzed': False,
                        u'count': 0,
                        u'doc_values': False,
          u'indexed': False,
          u'name': u'_index',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'_type',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'geoip.location',
          u'scripted': False,
          u'type': u'geo_point'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'@version',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': False,
          u'name': u'_source',
          u'scripted': False,
          u'type': u'_source'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': False,
          u'name': u'_id',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'request',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'agent',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'referrer.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'auth',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'ident',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'timestamp.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'response.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'clientip',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'host',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'bytes.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'timestamp',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'ident.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'clientip.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'host.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'verb',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'message',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'auth.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'referrer',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'httpversion.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'request.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'@timestamp',
          u'scripted': False,
          u'type': u'date'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'agent.raw',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'bytes',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'response',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': True,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'httpversion',
          u'scripted': False,
          u'type': u'string'},
         {u'analyzed': False,
          u'count': 0,
          u'doc_values': False,
          u'indexed': True,
          u'name': u'verb.raw',
          u'scripted': False,
          u'type': u'string'}]
    )


def create_index_patterns(url, username, config, request):
    version = url.rsplit('/', 1)[-1]
    orig_conf = json.loads(request.body)
    # url = elasticsearch/.kibana-test1/config/4.1.1

    indexes = config.get('autoindexes', config['indexes'])
    indexbase = settings.ES_UPSTREAM + '/.kibana-{0}'.format(username)

    for index in indexes:
        requests.put(indexbase + '/_mapping/index-pattern', data=json.dumps(
                     {"index-pattern": {"properties":
                                        {"title": {"type": "string"},
                                         "timeFieldName": {"type": "string"},
                                         "intervalName": {"type": "string"},
                                         "fields": {"type": "string"},
                                         "fieldFormatMap": {"type": "string"}
                                         }
                                        }
                      }))
        data = {'title': index, 'timeFieldName': '@timestamp'}
        if index.startswith('[') and ']' in index:
            data['intervalName'] = "days"
        requests.post(indexbase + '/index-pattern/{0}?op_type=create'
                      .format(index),
                      data=json.dumps(data))
        requests.post(indexbase + '/_refresh')
        data['fields'] = field_config()

        requests.post(indexbase + '/index-pattern/{0}'.format(index),
                      data=json.dumps(data))

    orig_conf['defaultIndex'] = indexes[0]
    requests.post(indexbase + '/config/{0}/_update'.format(version),
                  data=json.dumps({"doc": orig_conf}))


class LoginView(View):
    def get(self, request, *args, **kwargs):
        return render(request, "buckler/login.html")

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username in settings.CONFIG:
            crypt_hash = settings.CONFIG[username]['password']
            if crypt.crypt(password, crypt_hash) == crypt_hash:
                request.session['username'] = username
                open_indexes(settings.CONFIG[username])
                # indexes may not be ready at this point yet. Alternatively,
                # redirect to a url that checks the state of indexes and
                # keeps redirecting, possibly with a delay in the served html
                return redirect('/')
        return render(request, "buckler/login.html",
                      {'error': 'Invalid username or password'})


class InjectJSView(View):
    def get(self, request, *args, **kwargs):
        username, config = get_session(request)
        ctx = dict(username=username, logout=reverse("logout"),
                   poweruser=config.get('poweruser'))

        return render(request, 'buckler/inject.js', ctx,
                      content_type="application/javascript")


class LogoutView(View):
    def get(self, request, *args, **kwargs):
        del request.session['username']
        return redirect('/')


def get_full_url(url, request):
    """
        Construct the full (upstream) url
    """
    upstream = settings.KIBANA_UPSTREAM
    username, config = get_session(request)

    body = request.body

    parts = url.split('/')

    def index_allowed(index):
        """ Verify if access to the index is allowed by
            any of the config indexes """
        if index == ".kibana-" + username:
            return True

        for allowed_index in config.get('indexes', []):
            if fnmatch.fnmatch(index, allowed_index):
                return True
        return False

    def index_allowed_or_404(index):
        if not index_allowed(index):
            raise Http404("Access to index denied: {0}".format(index))

    def check_explicit_index(part):
        """ If there's an index in 'part' where the user does not have
            access to, raise 404 """

        indexes = part.split(",")
        for index in indexes:
            index_allowed_or_404(index)

    def check_mget_body():
        data = json.loads(body)
        for doc in data.get('docs', []):
            index = doc.get('_index')
            if index:
                index_allowed_or_404(index)

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
                    index_allowed_or_404(index)

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
            index_allowed_or_404(parts[1])
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

    param_str = request.GET.urlencode()
    request_url = u'%s/%s' % (upstream, url)
    request_url += '?%s' % param_str if param_str else ''
    # print "RESULT", request_url
    return request_url


class BucklerView(View):

    @require_authentication
    def get(self, request, url, *args, **kwargs):
        username, config = get_session(request)

        request_url = get_full_url(url, request)

        res = requests.get(request_url)

        data = res.content

        if url == "config":
            data_decode = json.loads(data)
            data_decode['kibana_index'] = ".kibana-{0}".format(username)
            data = json.dumps(data_decode)

        if url == '':  # / requested: inject javascript
            data = data.replace("</body>",
                                '<script src="{0}"></script></body>'
                                .format(reverse('injectjs')))

        return HttpResponse(data, status=res.status_code,
                            content_type=res.headers['content-type'])

    @require_authentication
    def post(self, request, url, *args, **kwargs):
        username, config = get_session(request)

        request_url = get_full_url(url, request)

        res = requests.post(request_url, data=request.body)

        if url.startswith("elasticsearch/.kibana-{0}/config/"
                          .format(username)) and res.status_code == 201:
            create_index_patterns(url, username, config, request)

        return HttpResponse(res.content, status=res.status_code,
                            content_type=res.headers['content-type'])

    @require_authentication
    def head(self, request, url, *args, **kwargs):
        return self.get(request, url, *args, **kwargs)

    @require_authentication
    def delete(self, request, url, *args, **kwargs):
        request_url = get_full_url(url, request)

        res = requests.delete(request_url, data=request.body)
        return HttpResponse(res.content, status=res.status_code,
                            content_type=res.headers['content-type'])

    @require_authentication
    def put(self, request, url, *args, **kwargs):
        request_url = get_full_url(url, request)

        res = requests.put(request_url, data=request.body)
        return HttpResponse(res.content, status=res.status_code,
                            content_type=res.headers['content-type'])
