from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from users.views import (InitialRegisterView,
                         VerifyOTPView,
                         ResendOTPView,
                         CompleteRegisterView,
                         LoginView,
                         LogoutView,
                         ForgotPasswordView,
                         ResetPasswordView,
                         ProfileUpdateView,
                         ProfileView )

urlpatterns = [
    # Register
    path('register/initial/', InitialRegisterView.as_view(), name='register_initial'),
    path('register/otp/', VerifyOTPView.as_view(), name='register_otp'),
    path('register/otpresend/', ResendOTPView.as_view(), name='register_otpresend'),
    path('register/complete/', CompleteRegisterView.as_view(), name='register_complete'),

    # Authentication
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # Password
    path('forgot/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset/', ResetPasswordView.as_view(), name='reset_password'),

    # Profile
    path('profile/', ProfileView.as_view(), name='profile'),
    path('profile/update/', ProfileUpdateView.as_view(), name='profile_update'),
]