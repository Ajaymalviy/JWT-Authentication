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




# Serializer for Register with role field
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
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(username=serializer.validated_data['username'],
                                password=serializer.validated_data['password'])
            if user is not None:
                # Create a unique session ID for this login
                session_id = str(uuid.uuid4())
                
                # Store or update the session ID in the database
                user_session, created = UserSession.objects.update_or_create(
                    user=user,
                    defaults={'session_id': session_id}
                )
                
                # Create JWT with session_id
                refresh = RefreshToken.for_user(user)
                refresh.payload['session_id'] = session_id  # Add session_id to JWT payload
                
                # Return JWT tokens
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                })
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
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
