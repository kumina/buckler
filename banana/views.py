import logging
import requests
import datetime
import urlparse

from django.http import HttpResponse
from django.views.generic import View
from django.shortcuts import render, redirect

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
                    'indexes': ('accounts', )}
         }

def log(method, path, type, headers, s):
    ## ignore anything that looks like a resource, for now.

    raw_path = urlparse.urlparse(path).path
    ext = raw_path.rsplit(".", 1)[-1]
    if ext in ('css', 'gif', 'js', 'ico', 'png', 'jpg', 'woff'):
        return

    with open("logfile", "a") as logfile:
        print >> logfile, "{0} {1} {2} {3}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), method, type, path)
        print >> logfile, str(headers)
        print >> logfile, s
        print >> logfile, "===================================="
        print >> logfile

allowed_indexes = ('logstash-ivo-',)

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

class LogoutView(View):
    def get(self, request, *args, **kwargs):
        del request.session['username']
        return redirect('/')


class BananaView(View):
    forward_url = "http://kibana:5601"

    """
    TODO:
    """

    def get_full_url(self, url):
        """
        Constructs the full URL to be requested.
        """
        if url.startswith("/elasticsearch/.kibana"):
            url = "/elasticsearch/.kibana-ivo" + url[22:]
        elif url.startswith("/elasticsearch/logstash-"):
            url = "/elasticsearch/logstash-ivo-" + url[24:]

        param_str = self.request.GET.urlencode()
        request_url = u'%s/%s' % (self.forward_url, url)
        request_url += '?%s' % param_str if param_str else ''
        return request_url

    def dispatch(self, *args, **kwargs):
        if not self.request.session.get('username'):
            return redirect('login')

        return super(BananaView, self).dispatch(*args, **kwargs)

    def get(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url)
        log("GET", request_url, "REQUEST", request.META, request.body)
        res = requests.get(request_url)
        log("GET", request_url, "RESPONSE", res.headers, res.content)

        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])

    def post(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url)
        log("POST", request_url, "REQUEST", request.META, request.body)

        body = request.body
        # data = json.loads(body)
        if '_msearch' in request_url:
            # import pdb; pdb.set_trace()
            body = body.replace("logstash-", "logstash-ivo-")
            
        res = requests.post(request_url, data=body)
        log("POST", request_url, "RESPONSE", res.headers, res.content)
        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])


    def head(self, request, url, *args, **kwargs):
        # print "HEAD called!", request, url
        return self.get(request, url, *args, **kwargs)

    def delete(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url)
        log("DELETE", request_url, "REQUEST", request.META, request.body)

        res = requests.delete(request_url, data=request.body)
        log("DELETE", request_url, "RESPONSE", res.headers, res.content)
        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])

    def put(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url)
        log("PUT", request_url, "PUT", request.META, request.body)

        res = requests.put(request_url, data=request.body)
        log("PUT", request_url, "RESPONSE", res.headers, res.content)
        return HttpResponse(res.content, status=res.status_code,
                content_type=res.headers['content-type'])

