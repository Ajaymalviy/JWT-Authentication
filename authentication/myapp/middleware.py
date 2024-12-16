from datetime import timedelta
from django.http import JsonResponse
from django.utils.timezone import now
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.models import User

class ActivityTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only track activity if the user is authenticated
        user = request.user
        if user.is_authenticated:
            # Check if the token has expired (and refresh if active)
            if self.token_is_expired(request):
                # Refresh token if the user is active
                self.refresh_token(user)
            
            # Check if the user has been inactive for more than 3 minutes
            last_activity = getattr(user, 'last_activity', None)
            if last_activity:
                time_inactive = (now() - last_activity).total_seconds()
                if time_inactive > 180:  # 3 minutes of inactivity
                    self.invalidate_session(user)
                    return JsonResponse({'message': 'Session expired due to inactivity'}, status=401)

            # Update last activity timestamp for the user
            user.last_activity = now()
            user.save()

        # Proceed with the request and get the response
        response = self.get_response(request)
        return response

    def token_is_expired(self, request):
        """
        Check if the access token in the request is expired.
        """
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split()[1]  # Extract Bearer token from the Authorization header
            try:
                # Check if the token is expired
                RefreshToken(token).check_expired()
                return True  # Token is expired
            except TokenError:
                return False  # Token is valid
        return False

    def refresh_token(self, user):
        """
        Refresh the JWT access token for the user if required.
        """
        # Refresh the access token for the user
        try:
            refresh = RefreshToken.for_user(user)
            # Update the access token in the response (if you need to pass the new access token back to the user)
            # In case you need to set it in response headers, you can modify the response object
            return True
        except Exception as e:
            return False

    def invalidate_session(self, user):
        """
        Invalidate the session if the user is inactive for too long.
        """
        if hasattr(user, 'auth_token'):
            # Delete the auth token to invalidate the session
            user.auth_token.delete()



# middleware.py
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.urls import resolve
from .models import UserSession

class SingleSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Skip JWT check for admin and login URLs
        if request.path.startswith('/admin/') or resolve(request.path_info).url_name in ['login', 'logout']:
            return response
        
        # Only check if the user is authenticated
        if request.user.is_authenticated:
            jwt_token = request.headers.get('Authorization', '').replace('Bearer ', '')
            
            if not jwt_token:
                raise AuthenticationFailed("Authentication token is missing.")
            
            try:
                # Validate the JWT token and extract the session ID
                jwt_auth = JWTAuthentication()
                validated_token = jwt_auth.get_validated_token(jwt_token)
                session_id_from_jwt = validated_token.payload['session_id']
                
                # Get the session ID stored in the database for this user
                user_session = UserSession.objects.get(user=request.user)
                
                # If session IDs don't match, raise an error
                if user_session.session_id != session_id_from_jwt:
                    raise AuthenticationFailed("Session expired or invalid.")
            
            except Exception as e:
                raise AuthenticationFailed(str(e))
        
        return response

