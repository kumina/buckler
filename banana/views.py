import logging
import requests
import datetime
import urlparse
import fnmatch

import json

from django.http import HttpResponse
from django.views.generic import View
from django.shortcuts import render, redirect
from django.http import Http404

logger = logging.getLogger(__name__)

"""
POST called! http://es:9200/_msearch?ignore_unavailable=true&preference=1440599351552&timeout=0 {"index":"logstash-*","ignore_unavailable":true}
{"size":500,"sort":[{"@timestamp":{"order":"desc","unmapped_type":"boolean"}}],"query":{"filtered":{"query":{"query_string":{"analyze_wildcard":true,"query":"GET"}},"filter":{"bool":{"must":[{"range":{"@timestamp":{"gte":1420066800000,"lte":1451602799999}}}],"must_not":[]}}}},"highlight":{"pre_tags":["@kibana-highlighted-field@"],"post_tags":["@/kibana-highlighted-field@"],"fields":{"*":{}},"fragment_size":2147483647},"aggs":{"2":{"date_histogram":{"field":"@timestamp","interval":"1w","pre_zone":"+02:00","pre_zone_adjust_large_interval":true,"min_doc_count":0,"extended_bounds":{"min":1420066800000,"max":1451602799999}}}},"fields":["*","_source"],"script_fields":{},"fielddata_fields":["@timestamp"]}

[26/Aug/2015 14:29:12] "POST /_msearch?timeout=0&ignore_unavailable=true&preference=1440599351552 HTTP/1.1" 200 631675

"""

"""
TODO


"""

config = { 'ivo': {'password':'1v0',
                   'indexes': ('logstash-ivo-*',)},
           'test': {'password': 't3st',
                    'indexes': ('accounts', )},
           'superuser': {'password': 'geheim',
                         'indexes':('accounts', 'logstash-*', 'logstash-ivo-*')}
         }

def get_session(request):
    username = request.session.get('username')

    if username:
        return username, config.get(username)
    return None, None

def log(method, path, type, headers, s):
    ## ignore anything that looks like a resource, for now.

    raw_path = urlparse.urlparse(path).path
    ext = raw_path.rsplit(".", 1)[-1]
    if ext in ('css', 'gif', 'js', 'ico', 'png', 'jpg', 'woff'):
        return

    with open("logfile", "a") as logfile:
        print >> logfile, "{0} {1} {2} {3}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), method, type, path)
        # print >> logfile, str(headers)
        print >> logfile, s
        print >> logfile, "===================================="
        print >> logfile

from django.core.urlresolvers import reverse

class LoginView(View):
    def get(self, request, *args, **kwargs):
        return render(request, "banana/login.html")

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username in config and config[username]['password'] == password:
            request.session['username'] = username
            return redirect('/')
        else:
            return render(request, "banana/login.html", {'error':'Invalid username or password'})

class InjectJSView(View):
    def get(self, request, *args, **kwargs):
        username, config = get_session(request)
        js = """
            function inject() {{
            console.log("Start injection");
            console.log($);
            $("div.navbar-collapse").append('<ul class="nav navbar-nav pull-right"><li><a href="{logout}">Logout {username}</a></li></ul>');
            }}
            setTimeout(inject, 3000);
        """.format(username=username, logout=reverse("logout"))
        return HttpResponse(js, status=200,
                content_type="application/javascript")

class LogoutView(View):
    def get(self, request, *args, **kwargs):
        del request.session['username']
        return redirect('/')


class BananaView(View):
    KIBANA_UPSTREAM = "http://kibana:5601"
    ES_UPSTREAM = "http://es:9200"

    """
    TODO:
    """

    def get_full_url(self, url, request):
        """
            Construct the full (upstream) url
        """
        upstream = self.KIBANA_UPSTREAM
        username, config = get_session(self.request)

        body = request.body

        parts = url.split('/')

        def check_explicit_index(part):
            indexes = part.split(",")
            for index in indexes:
                if index not in config['indexes']:
                    raise Http404("Invalid access or request")

        def check_mget_body():
            data = json.loads(body)
            for doc in data.get('docs', []):
                index = doc.get('_index')
                if index:
                    if index == ".kibana-" + username:
                        continue
                    for allowed_index in config['indexes']:
                        if fnmatch.fnmatch(index, allowed_index):
                            break
                    else:
                        raise Http404("Access to index denied: {0}".format(index))

        def check_msearch_body():
            for line in body.splitlines():
                data = json.loads(line)
                if 'index' in data:
                    index = data.get('index')
                    for allowed_index in config['indexes']:
                        if fnmatch.fnmatch(index, allowed_index):
                            break
                    else:
                        raise Http404("Access to index denied: {0}".format(index))


        if parts[0].lower() == 'elasticsearch' and len(parts) > 1:
            # /elasticsearch/ and /elasticsearch/_nodes
            if parts[1] in ('', '_nodes'):
                pass # allowed
            # /elasticsearch/.kibana-someuser
            elif parts[1].startswith(".kibana"):
                # bypass kibana, go directly to ES since kibana will not allow
                # us to access any other ".kibana" index than the configured one
                upstream = self.ES_UPSTREAM
                url = url.split('/', 1)[1]
            # /elasticsearch/_all or /elasticsearch/_query
            elif parts[1] in ('_all', '_query'):
                ## include .kibana-<username> ?
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
                indexes = parts[1].split(",")
                for index in indexes:
                    if index not in config['indexes']:
                        raise Http404("Invalid access or request")

        param_str = self.request.GET.urlencode()
        request_url = u'%s/%s' % (upstream, url)
        request_url += '?%s' % param_str if param_str else ''
        print "RESULT", request_url
        return request_url

    def dispatch(self, *args, **kwargs):
        if not get_session(self.request)[0]:
            return redirect('login')

        return super(BananaView, self).dispatch(*args, **kwargs)

    def get(self, request, url, *args, **kwargs):
        username, config = get_session(request)

        request_url = self.get_full_url(url, request)
        log("GET", request_url, "REQUEST", request.META, request.body)
        res = requests.get(request_url)
        log("GET", request_url, "RESPONSE", res.headers, res.content)

        data = res.content

        if url == "config":
            data_decode = json.loads(data)
            data_decode['kibana_index'] = ".kibana-{0}".format(username)
            data = json.dumps(data_decode)

        if url == '':
            data = data.replace("</body>", '<script src="/inject.js"></script></body>')


        return HttpResponse(data, status=res.status_code,
                content_type=res.headers['content-type'])

    def post(self, request, url, *args, **kwargs):
        # import pdb; pdb.set_trace()

        username, config = get_session(request)

        request_url = self.get_full_url(url, request)
        log("POST", request_url, "REQUEST", request.META, request.body)

        res = requests.post(request_url, data=request.body)
        log("POST", request_url, "RESPONSE", res.headers, res.content)
        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])


    def head(self, request, url, *args, **kwargs):
        # print "HEAD called!", request, url
        return self.get(request, url, *args, **kwargs)

    def delete(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url, request)
        log("DELETE", request_url, "REQUEST", request.META, request.body)

        res = requests.delete(request_url, data=request.body)
        log("DELETE", request_url, "RESPONSE", res.headers, res.content)
        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])

    def put(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url, request)
        log("PUT", request_url, "PUT", request.META, request.body)

        res = requests.put(request_url, data=request.body)
        log("PUT", request_url, "RESPONSE", res.headers, res.content)
        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])

