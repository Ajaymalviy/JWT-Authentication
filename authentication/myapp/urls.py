# auth_app/urls.py
from django.urls import path
from .views import RegisterView, LoginView,  SamlLoginView, SamlACSView, ProtectedView
from rest_framework_simplejwt import views as jwt_views
from myapp import views

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('sso/login/', SamlLoginView.as_view(), name='saml_login'),  # SAML login redirect
    path('sso/acs/', SamlACSView.as_view(), name='saml_acs'),  # SAML Assertion Consumer Service (ACS) endpoint
    path('protected/', ProtectedView.as_view(), name='protected'),

]

