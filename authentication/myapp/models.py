# models.py
from django.db import models
from django.contrib.auth.models import User

class UserSession(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    session_id = models.CharField(max_length=255, unique=True)
    last_updated = models.DateTimeField(auto_now=True)
