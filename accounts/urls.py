from django.urls import path
from . import views

# URL patterns for the application
urlpatterns = [
    # Home page
    path('', views.home, name='home'),
    
    # Authentication routes
    path('login/', views.login_view, name='login'),
    path('otp-login/', views.otp_login, name='otp_login'),
    path('signup/', views.signup_view, name='signup'),
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),
    path('logout/', views.logout_view, name='logout'),
    
    # Password and username recovery routes
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<uuid:token>/', views.reset_password, name='reset_password'),
    path('forgot-username/', views.forgot_username, name='forgot_username'),
    path('verify-username-otp/', views.verify_username_otp, name='verify_username_otp'),
    
    # User profile and document management routes
    path('profile/', views.profile_view, name='profile'),
    path('upload/', views.upload_view, name='upload'),
    path('download/<str:cid>/<str:filename>/', views.download_document, name='download_document'),
    path('share/', views.share_document, name='share_document'),
    path('access-shared/<uuid:token>/', views.access_shared_document, name='access_shared_document'),
]