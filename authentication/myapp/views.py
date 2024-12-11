from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers

# Serializer for Register
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            email=validated_data['email']
        )
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


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(username=serializer.validated_data['username'],
                                password=serializer.validated_data['password'])
            if user is not None:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                })
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# auth_app/views.py (Add this to your existing views)
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "This is a protected view, you are authenticated!"})



#----------------------------------------------------------------------

# from django.shortcuts import render
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate
# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.permissions import IsAuthenticated
# from rest_framework import serializers
# import logging



# # Serializer for Register (No changes needed)
# class RegisterSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ['username', 'password', 'email']
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self, validated_data):
#         user = User.objects.create_user(
#             username=validated_data['username'],
#             password=validated_data['password'],
#             email=validated_data['email']
#         )
#         return user
    

#     # # Serializer for Login
# class LoginSerializer(serializers.Serializer):
#     username = serializers.CharField()
#     password = serializers.CharField()


# # Register and Login Views remain unchanged
# class RegisterView(APIView):
#     def post(self, request):
#         serializer = RegisterSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()
#             return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LoginView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             user = authenticate(username=serializer.validated_data['username'],
#                                 password=serializer.validated_data['password'])
#             if user is not None:
#                 refresh = RefreshToken.for_user(user)
#                 return Response({
#                     'access': str(refresh.access_token),
#                     'refresh': str(refresh)
#                 })
#             return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# # New view to handle SAML login
# class SamlLoginView(APIView):
#     def get(self, request):
#         # this is where saml triggered you at login page.
#         return Response({"message": "Redirect to SAML Identity Provider for authentication."})



# class SamlACSView(APIView):
#     def post(self, request):
#         # Assuming that the SAML Assertion is handled here, and the user is authenticated.
#         # You would extract the user's data from the SAML response.

#         # For the sake of simplicity, assume the extracted user data:
#         user_data = {
#             'username': request.data.get('username'),
#             'first_name': request.data.get('first_name'),
#             'last_name': request.data.get('last_name')
#         }

#         # Check if the user exists or create a new user
#         user, created = User.objects.get_or_create(username=user_data['username'])

#         # Set the user's information
#         user.first_name = user_data['first_name']
#         user.last_name = user_data['last_name']
#         user.save()

#         # Generate the JWT (access token)
#         refresh = RefreshToken.for_user(user)
#         access_token = str(refresh.access_token)
#         print("Refresh:", refresh)
#         print("access_token:",access_token)

#         # Return the JWT to the user
#         return Response({
#             'access': access_token,
#             'refresh': str(refresh)
#         })

# # Protected view requiring JWT authentication
# class ProtectedView(APIView):
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         return Response({"message": "This is a protected view, you are authenticated!"})
