# models.py
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lockout_time = models.DateTimeField(null=True, blank=True)

    #create a function for lock the user by time
    def is_locked(self):
        if self.lockout_time:
            if timezone.now() > self.lockout_time + timedelta(minutes=15):
                # Reset after lock period
                self.failed_login_attempts = 0
                self.lockout_time = None
                self.save()
                return False  # User is not locked anymore
            return True  # User is still locked
        return False  # User has no lockout time


class UserSession(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    session_id = models.CharField(max_length=255, unique=True)
    last_updated = models.DateTimeField(auto_now=True)
