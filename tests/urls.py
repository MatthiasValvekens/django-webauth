from django.urls import path, include
from . import views
import webauth.urls

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
]

urlpatterns = [
    path('webauth/', include(webauth.urls)),
    path('tokens/', include(token_testing))
]
