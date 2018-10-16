from django.urls import path
from webauth import views

urlpatterns = [
    # override login view
    #  Note: since we want to override the url, not the name,
    # this needs to go *before* the include(...)
    path('login/', views.LoginI18NRedirectView.as_view(), name='login'), 
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('password_change/', 
         views.PasswordChangeView.as_view(), name='password_change'),
    path('password_change/done/', 
         views.PasswordChangeDoneView.as_view(), name='password_change_done'),
    path('password_reset/', 
         views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', 
         views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), 
         name='password_reset_confirm'),
    path('reset/done/', views.PasswordResetCompleteView.as_view(), 
         name='password_reset_complete'),
    path('activate/<uidb64>/<token>/', 
         views.ActivateAccountView.as_view(), name='activate_account'),
    path('unlock/<uidb64>/<token>/', 
         views.unlock_account_view, name='unlock_account'),
    path('activate/done/', 
         views.AccountActivatedView.as_view(), name='account_activated'),
    path('reset_email/', views.email_reset_view, name='reset_email'),
    path('confirm_password/', 
         views.PasswordConfirmView.as_view(), name='confirm_password'),
    path('otp_login/', views.OTPLoginView.as_view(), name='otp_login'),
]
