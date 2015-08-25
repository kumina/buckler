import logging
import requests

from django.http import HttpResponse
from django.views.generic import View

logger = logging.getLogger(__name__)

class BananaView(View):
    forward_url = "http://es:9200"

    """
    TODO:
    """

    def get_full_url(self, url):
        """
        Constructs the full URL to be requested.
        """
        param_str = self.request.GET.urlencode()
        request_url = u'%s/%s' % (self.forward_url, url)
        request_url += '?%s' % param_str if param_str else ''
        return request_url

    def get(self, request, url, *args, **kwargs):
        request_url = self.get_full_url(url)
        res = requests.get(request_url)
        return HttpResponse(res.text, status=res.status_code,
                content_type=res.headers['content-type'])

    def post(self, request, url, *args, **kwargs):
        print "POST called!", request, url
        request_url = self.get_full_url(url)
        res = requests.post(request_url, data=request.body)
        return HttpResponse(res.text, status=res.status_code,
                content_type=res.headers['content-type'])


    def head(self, request, url, *args, **kwargs):
        print "HEAD called!", request, url
        return self.get(request, url, *args, **kwargs)

