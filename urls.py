from django.urls import include, path
from webauth.views import (
    ActivateAccountView, AccountActivatedView, LoginI18NRedirectView,
    email_reset_view, unlock_account_view, OTPLoginView
)


urlpatterns = [
    # override login view
    #  Note: since we want to override the url, not the name,
    # this needs to go *before* the include(...)
    path('login/', LoginI18NRedirectView.as_view(), name='login'),
    path('', include('django.contrib.auth.urls')),
    path('activate/<uidb64>/<token>/', 
        ActivateAccountView.as_view(), name='activate_account'),
    path('unlock/<uidb64>/<token>/', 
        unlock_account_view, name='unlock_account'),
    path('activate/done/', 
        AccountActivatedView.as_view(), name='account_activated'),
    path('reset_email/', email_reset_view, name='reset_email'),
    path('otp_login/', OTPLoginView.as_view(), name='otp_login'),
]
