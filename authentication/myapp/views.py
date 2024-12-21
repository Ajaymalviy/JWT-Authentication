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



from django.shortcuts import render

def login_view(request):
    print('i am at login view')
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
    # recaptcha_token = serializers.CharField()  

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




def verify_recaptcha(token):
    print('i am at verify recaptcha')
    secret_key = settings.RECAPTCHA_SECRET_KEY  # Ensure this is set in your settings.py
    print('secrete key is ', secret_key)
    url = 'https://www.google.com/recaptcha/api/siteverify'

    payload = {
        'secret': secret_key,
        'response': token
    }

    print(f"Sending payload: {payload}")  # Log the payload
    response = requests.post(url, data=payload)
    print(f"Response: {response.text}")  # Log the full response from Google


    result = response.json()
    print('result is ', result)
    # Only return the 'success' field
    return result.get('success', False)



# import uuid
# class LoginView(APIView):
#     def post(self, request):
#         # Deserialize the data (username, password, and recaptcha_token)
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             # print("inside valid serializer function")
#             # recaptcha_token = serializer.validated_data['recaptcha_token']
#             # print('recaptcha_token', recaptcha_token)
#             # # Step 1: Verify reCAPTCHA token
#             # success = verify_recaptcha(recaptcha_token)
#             # print('successs checking ', success)
#             # if not success:
#             #     # Reject login if reCAPTCHA validation fails
#             #     return Response({"error": "Invalid reCAPTCHA. Please try again."}, status=status.HTTP_400_BAD_REQUEST)

#             # Step 2: Authenticate user with username and password
#             user = authenticate(username=serializer.validated_data['username'],
#                                 password=serializer.validated_data['password'])
#             if user is not None:
#                 # Step 3: Create a unique session ID for this login
#                 session_id = str(uuid.uuid4())

#                 # Step 4: Store or update the session ID in the database
#                 user_session, created = UserSession.objects.update_or_create(
#                     user=user,
#                     defaults={'session_id': session_id}
#                 )

#                 # Step 5: Create JWT with session_id
#                 refresh = RefreshToken.for_user(user)
#                 refresh.payload['session_id'] = session_id  # Add session_id to JWT payload

#                 # Return the JWT tokens
#                 return Response({
#                     'access': str(refresh.access_token),
#                     'refresh': str(refresh)
#                 })
#             return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

#         # If serializer is not valid, return errors
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# import uuid
# from django.contrib.auth import authenticate
# from django.utils import timezone
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import UserProfile  # Import UserProfile model

# class LoginView(APIView):
#     def post(self, request):
#         # Deserialize the data (username, password)
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             username = serializer.validated_data['username']
#             password = serializer.validated_data['password']

#             # Get the user object
#             try:
#                 user = User.objects.get(username=username)
#             except User.DoesNotExist:
#                 return Response({"error": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

#             # Get the user profile (related to the user model)
#             user_profile, created = UserProfile.objects.get_or_create(user=user)

#             # Check if the user is locked
#             if user_profile.is_locked():
#                 return Response({"error": "Account locked. Please try again later."}, status=status.HTTP_403_FORBIDDEN)

#             # Authenticate user with username and password
#             user = authenticate(username=username, password=password)

#             if user is None:
#                 # Increment failed login attempts and lock user if necessary
#                 user_profile.failed_login_attempts += 1
#                 if user_profile.failed_login_attempts >= 3:
#                     user_profile.lockout_time = timezone.now()  # Lock user for 15 minutes
#                 user_profile.save()
#                 return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

#             # Reset failed login attempts on successful login
#             user_profile.failed_login_attempts = 0
#             user_profile.lockout_time = None
#             user_profile.save()

#             # Create a unique session ID for this login
#             session_id = str(uuid.uuid4())

#             # Step 4: Store or update the session ID in the database (you might have a session model for this)
#             user_session, created = UserSession.objects.update_or_create(
#                 user=user,
#                 defaults={'session_id': session_id}
#             )

#             # Step 5: Create JWT with session_id
#             refresh = RefreshToken.for_user(user)
#             refresh.payload['session_id'] = session_id  # Add session_id to JWT payload

#             # Return the JWT tokens
#             return Response({
#                 'access': str(refresh.access_token),
#                 'refresh': str(refresh)
#             })

#         # If serializer is not valid, return errors
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from django.core.cache import cache
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
import uuid
from datetime import timedelta

# Constants
MAX_ATTEMPTS = 3
BLOCK_TIME = 15 * 60  # Lock time in seconds (15 minutes)

class LoginView(APIView):
    def post(self, request):
        # Deserialize the data (username, password)
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

          
            ip_address = self.get_client_ip(request)
            print('ip address is ',ip_address)
            attempts_key = f"login_attempts_{ip_address}"
            print('attempts_key is ', attempts_key)

            block_key = f"blocked_{ip_address}"
            print('block_key is ', block_key)


            if cache.get(block_key):
                return Response({"error": "Too many login attempts. Please try again later."}, status=status.HTTP_403_FORBIDDEN)

            try:
                user = User.objects.get(username=username)
                print('user is someone ', user)
            except User.DoesNotExist:
                return Response({"error": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)

            # Authenticate the user
            user = authenticate(username=username, password=password)
            

            if user is None:
                # Increment failed login attempts and block IP if necessary
                failed_attempts = cache.get(attempts_key, 0)
                failed_attempts += 1
                print('failed attempts is ', failed_attempts)

                if failed_attempts >= MAX_ATTEMPTS:
                    cache.set(block_key, True, BLOCK_TIME)

                # Store the updated failed attempts count in cache
                cache.set(attempts_key, failed_attempts, BLOCK_TIME)

                return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

            cache.delete(attempts_key)

            session_id = str(uuid.uuid4())

            # Step 4: You can store or update the session ID in the database if you have a session model
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

        # If serializer is not valid, return errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_client_ip(self, request):
        """Returns the client's IP address."""
        print('ip address is ')
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        print('something forwarded like ',x_forwarded_for)
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
            print('done' ,ip)
        else:
            ip = request.META.get('REMOTE_ADDR')
            print('done', ip)
        return ip



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
