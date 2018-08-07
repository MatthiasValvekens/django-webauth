from django.urls import include, path
from webauth.views import (
    ActivateAccountView, AccountActivatedView, LoginI18NRedirectView
)


urlpatterns = [
    # override login view
    #  Note: since we want to override the url, not the name,
    # this needs to go *before* the LoginI18NRedirectView
    path('login/', LoginI18NRedirectView.as_view(), name='login'),
    path('', include('django.contrib.auth.urls')),
    path('activate/<uidb64>/<token>/', 
        ActivateAccountView.as_view(), name='activate_account'),
    path('activate/done/', 
        AccountActivatedView.as_view(), name='account_activated'),
]
