# auth_app/urls.py
from django.urls import path
from .views import RegisterView, LoginView, ProtectedView
from rest_framework_simplejwt import views as jwt_views
from myapp import views

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected')

]
