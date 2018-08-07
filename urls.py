from django.urls import include, path
from webauth.views import ActivateAccountView, AccountActivatedView


urlpatterns = [
    path('', include('django.contrib.auth.urls')),
    path('activate/<uidb64>/<token>/', 
        ActivateAccountView.as_view(), name='activate_account'),
    path('activate/done/', 
        AccountActivatedView.as_view(), name='account_activated'),
]
