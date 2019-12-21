from django.http import HttpResponseNotFound
from django.urls import path, include
from . import views
import webauth.urls

def handler404(request, exception=None):
    exc_str = 'not found' if exception is None else str(exception)
    return HttpResponseNotFound(exc_str)

token_testing = [
    path('simple_view/<int:stuff>/<str:token>/', views.simple_view, name='simple_view'),
    path('simple_view/<int:stuff>/', views.simple_view, name='simple_view_notoken'),
    path('simple_view2/<int:stuff>/<str:foo>/<str:bar>/<str:token>/', 
            views.simple_view_with_more_args, name='simple_view_with_more_args'),
    path('simple_cbv/<int:stuff>/<str:foo>/<str:bar>/<str:token>/', 
            views.SimpleCBV.as_view(), name='simple_cbv'),
    path('objtok_email/<int:pk>/<str:token>/',
         views.SimpleCustomerCBV.as_view(), name='objtok_email'),
    path('objtok_hidden/<int:pk>/<str:token>/',
         views.SimpleCustomerCBV2.as_view(), name='objtok_hidden'),
    path('objtok_timebased/<int:pk>/<str:token>/',
         views.SimpleCustomerCBV3.as_view(), name='objtok_timebased'),
    path('customer/<int:pk>/<str:token>/',
         views.simple_customer_view, name='simple_cust_view'),
    path('customer/<int:pk>/',
         views.simple_customer_session_view, name='simple_cust_session_view'),
    path('bad1/<str:token>/', views.BadDbTokenMixin.as_view(), name='bad_db_token_view'),
    path('bad2', views.bad_session_view, name='bad_session_token_view'),
    path('pwconfirm', views.is_password_confirmed, name='password_confirm_required'),
    path('badcustview/<str:token>/', views.bad_customer_view, name='bad_customer_view'),
    path('api/', include(views.testing_api.endpoint_urls))
]

urlpatterns = [
    path('webauth/', include(webauth.urls)),
    path('tokens/', include(token_testing))
]
