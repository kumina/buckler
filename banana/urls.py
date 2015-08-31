from django.conf.urls import include, url
from django.contrib import admin

from .views import BananaView, LoginView, LogoutView


urlpatterns = [
    url(r'@login$', LoginView.as_view(), name='login'),
    url(r'@logout$', LogoutView.as_view(), name='logout'),
    url(r'(?P<url>.*)$', BananaView.as_view())
]
