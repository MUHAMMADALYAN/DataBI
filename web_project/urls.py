from django.contrib import admin
from django.urls import path
from app import views as app_views
from django.contrib.auth import views as auth_views
from datetime import datetime
from django.conf.urls import include, url
from app.forms import BootstrapAuthenticationForm
from django.contrib.auth.views import HttpResponseRedirect

from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    url(r'^applogout', app_views.applogout, name='applogout'),
    url(r'^callback', app_views.callback, name='callback'),
    url(r'^revoke', app_views.revoke, name='revoke'),
    url(r'^$', app_views.home, name='home'),
    url(r'^login/$',
        auth_views.LoginView.as_view(
            template_name='app/login.html', 
            authentication_form=BootstrapAuthenticationForm,
            extra_context= {
                'title':'Log in',
                'year':datetime.now().year,
            }
        ),
        name='login'),
    url(r'^logout$',
        auth_views.LogoutView.as_view(),
        {
            'next_page': '/',
        },
        name='logout'),

    url(r'^admin/', admin.site.urls),
]
