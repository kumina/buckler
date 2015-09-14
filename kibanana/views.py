import requests
import fnmatch

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



class LoginView(View):
    def get(self, request, *args, **kwargs):
        return render(request, "kibanana/login.html")

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username in settings.CONFIG and settings.CONFIG[username]['password'] == password:
            request.session['username'] = username
            return redirect('/')
        else:
            return render(request, "kibanana/login.html", {'error':'Invalid username or password'})

class InjectJSView(View):
    def get(self, request, *args, **kwargs):
        username, config = get_session(request)
        js = """
            function inject() {{
            console.log("Start injection");
            console.log($);
            $("div.navbar-collapse").append('<ul class="nav navbar-nav"><li><a href="{logout}"><i class="fa fa-sign-out"></i> Logout {username}</a></li></ul>');
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

    def get_full_url(self, url, request):
        """
            Construct the full (upstream) url
        """
        upstream = settings.KIBANA_UPSTREAM
        username, config = get_session(self.request)

        body = request.body

        parts = url.split('/')

        def check_explicit_index(part):
            indexes = part.split(",")
            for index in indexes:
                if index == ".kibana-" + username:
                    continue
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
            # /elasticsearch/_cluster/health/.kibana-<user>
            elif parts[1] == '_cluster':
                check_explicit_index(parts[-1])
            # /elasticsearch/.kibana-someuser
            elif parts[1].startswith(".kibana"):
                # bypass kibana, go directly to ES since kibana will not allow
                # us to access any other ".kibana" index than the configured one
                upstream = settings.ES_UPSTREAM
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

        res = requests.get(request_url)

        data = res.content

        if url == "config":
            data_decode = json.loads(data)
            data_decode['kibana_index'] = ".kibana-{0}".format(username)
            data = json.dumps(data_decode)

        if url == '': # / requested: inject javascript
            data = data.replace("</body>", '<script src="/inject.js"></script></body>')


        return HttpResponse(data, status=res.status_code,
                content_type=res.headers['content-type'])

    def post(self, request, url, *args, **kwargs):
        # import pdb; pdb.set_trace()

        username, config = get_session(request)

        request_url = self.get_full_url(url, request)

        res = requests.post(request_url, data=request.body)
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

