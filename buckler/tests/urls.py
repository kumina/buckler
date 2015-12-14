from django.conf.urls import url

from ..views import BucklerView, LoginView, LogoutView, InjectJSView


urlpatterns = [
    url(r'^inject\.js$', InjectJSView.as_view(), name='injectjs'),
    url(r'@login$', LoginView.as_view(), name='login'),
    url(r'@logout$', LogoutView.as_view(), name='logout'),
    url(r'(?P<url>.*)$', BucklerView.as_view())
]
