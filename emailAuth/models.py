from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser
from django.contrib import admin

from django.contrib.auth import get_user_model




class User(AbstractUser):
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    flutterwave_account_number = models.CharField(max_length=50, blank=True, null=True)
    flutterwave_bank_name = models.CharField(max_length=100, blank=True, null=True)
    flutterwave_account_name = models.CharField(max_length=100, blank=True, null=True)
    is_verified = models.BooleanField(default=False)  # New field to track email verification


class Voice(models.Model):
    # For system voices, user can be null (so sample audio is shared).
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='voices', null=True, blank=True)
    name = models.CharField(max_length=255)
    avatar_path = models.CharField(max_length=255, blank=True)
    sample_audio = models.URLField(blank=True, null=True)  # Allow null values
    elevenlabs_voice_id = models.CharField(max_length=255, blank=True)  # returned by Elevenlabs
    is_public = models.BooleanField(default=False)  # False for user-specific cloned voices
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']





class TTSConversion(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tts_requests')
    text = models.TextField()
    voice = models.ForeignKey(Voice, on_delete=models.SET_NULL, null=True, blank=True)
    cost = models.DecimalField(max_digits=10, decimal_places=2)
    audio_url = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)




class UserHistory(models.Model):
    ACTION_CHOICES = (
        ('tts', 'Text to Speech'),
        ('clone', 'Voice Clone'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="history")
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    title = models.CharField(max_length=255, blank=True, null=True)  # New title field for display
    media = models.FileField(upload_to='user_history/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title if self.title else (self.media.name if self.media else "No Media")


class Payment(models.Model):
    PAYMENT_METHOD_CHOICES = (
        ('opay', 'OPay'),
        ('nowpayments', 'NowPayments'),
        ('flutterwave', 'Flutterwave'),
    )
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    method = models.CharField(max_length=50, choices=PAYMENT_METHOD_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10)  # e.g. NGN, USD
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    transaction_id = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
