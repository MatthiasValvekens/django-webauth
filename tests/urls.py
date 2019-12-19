from django.urls import path, include
from . import views
import webauth.urls

token_testing = [
    path('simple_view/<int:stuff>/<str:token>/', views.simple_view, name='simple_view'),
    path('simple_view2/<int:stuff>/<str:foo>/<str:bar>/<str:token>/', 
            views.simple_view_with_more_args, name='simple_view_with_more_args'),
]

urlpatterns = [
    path('webauth/', include(webauth.urls)),
    path('tokens/', include(token_testing))
]
