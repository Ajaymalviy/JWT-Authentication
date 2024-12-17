from django.contrib.auth.models import User
from django.http import HttpResponse
from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated,BasePermission
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from .models import UserSession
from django.conf import settings
import requests

from django.shortcuts import render


# Helper function to verify reCAPTCHA token
import requests
from django.conf import settings

import requests
from django.conf import settings

# Helper function to verify reCAPTCHA token
def verify_recaptcha(token):
    secret_key = settings.RECAPTCHA_SECRET_KEY  # Ensure this is set in your settings.py
    url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': secret_key,
        'response': token
    }
    response = requests.post(url, data=payload)
    result = response.json()
    
    # Only return the 'success' field
    return result.get('success', False)


from django.shortcuts import render

def login_view(request):
    # Pass the reCAPTCHA site key from settings to the template
    print('recaptcha' ,settings.RECAPTCHA_SITE_KEY)
    return render(request, 'login.html', {
        'recaptcha_site_key': settings.RECAPTCHA_SITE_KEY
    })


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'role']  # Include role field
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        # Check if the role is valid before creating the user
        role = validated_data.get('role', 'user')  # Default role is 'user'
        if role not in ['admin', 'user','customer']:
            raise serializers.ValidationError({"role": "Invalid role. Choose either 'admin' or 'user'."})

        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email']
        )
        # You can add a role field in the user's profile if you want to keep it outside the user model.
        user.profile.role = role  
        user.save()

        return user

# Serializer for Login
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    recaptcha_token = serializers.CharField()  

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



import uuid
class LoginView(APIView):
    def post(self, request):
        # Deserialize the data (username, password, and recaptcha_token)
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            recaptcha_token = serializer.validated_data['recaptcha_token']
            
            # Step 1: Verify reCAPTCHA token
            success = verify_recaptcha(recaptcha_token)
            if not success:
                # Reject login if reCAPTCHA validation fails
                return Response({"error": "Invalid reCAPTCHA. Please try again."}, status=status.HTTP_400_BAD_REQUEST)

            # Step 2: Authenticate user with username and password
            user = authenticate(username=serializer.validated_data['username'],
                                password=serializer.validated_data['password'])
            if user is not None:
                # Step 3: Create a unique session ID for this login
                session_id = str(uuid.uuid4())

                # Step 4: Store or update the session ID in the database
                user_session, created = UserSession.objects.update_or_create(
                    user=user,
                    defaults={'session_id': session_id}
                )

                # Step 5: Create JWT with session_id
                refresh = RefreshToken.for_user(user)
                refresh.payload['session_id'] = session_id  # Add session_id to JWT payload

                # Return the JWT tokens
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                })
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # If serializer is not valid, return errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework.permissions import BasePermission
class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            # Check if the user is a staff member (admin)
            return request.user.is_staff
        return False

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Define your HTML content
        html_content = """
        <html>
            <head><title>Protected Page</title></head>
            <body>
                <h1>Welcome, you are authenticated!</h1>
                <p>This is a protected view.</p>
            </body>
        </html>
        """

        # Return the HTML content as an HTTP response
        return HttpResponse(html_content, content_type="text/html")
    
    
class IsAdmin(BasePermission):
    """
    Custom permission to allow only users with 'admin' role.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and if their role is 'admin'
        if request.user and request.user.is_authenticated:
            return request.user.role == 'admin'  # Assuming `role` is directly on User or Profile
        return False


class ProtectedViewd(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  
    def get(self, request):
        return Response({"message": "This is a protected view, only accessible by admins!"})

    
class IsAdminOrModerator(BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            # Check if the user has one of the roles: 'admin' or 'moderator'
            return request.user.profile.role in ['admin', 'customer']
        return False

class ProtectedViewForAdminOrModerator(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrModerator]

    def get(self, request):
        return Response({"message": "This is a protected view, accessible by admins or customer!"})


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Invalidate the session by deleting it from the database
        UserSession.objects.filter(user=request.user).delete()
        
        return Response({"message": "Logged out successfully."})
