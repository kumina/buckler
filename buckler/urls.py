from django.conf.urls import include, url
from django.contrib import admin
from django.views.decorators.csrf import csrf_exempt

from .views import BucklerView, LoginView, LogoutView, InjectJSView


urlpatterns = [
    url(r'^inject\.js$', InjectJSView.as_view(), name='injectjs'),
    url(r'@login$', LoginView.as_view(), name='login'),
    url(r'@logout$', LogoutView.as_view(), name='logout'),
    url(r'(?P<url>.*)$', csrf_exempt(BucklerView.as_view()))
]
