from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('otp-login/', views.otp_login, name='otp_login'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uuid:token>/', views.reset_password, name='reset_password'),
    path('forgot-username/', views.forgot_username, name='forgot_username'),
    path('verify-username-otp/', views.verify_username_otp, name='verify_username_otp'),
    path('signup/', views.signup_view, name='signup'),
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('upload/', views.upload_view, name='upload'),
    path('download/<str:cid>/<str:filename>', views.download_document, name='download_document'),

]