from django.conf.urls import include, url
from django.contrib import admin

from .views import BananaView


urlpatterns = [
    url(r'(?P<url>.*)$', BananaView.as_view())
]
