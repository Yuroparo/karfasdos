import os
import requests
from decimal import Decimal
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.db.models import Q
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Voice, TTSConversion, User, UserHistory, Payment
from .serializers import VoiceSerializer, TTSConversionSerializer, TopUpSerializer, UserHistorySerializer, PaymentSerializer

# --- Elevenlabs helper functions ---
ELEVENLABS_API_KEY = 'your_elevenlabs_api_key'
ELEVENLABS_TTS_URL = 'https://api.elevenlabs.io/v1/text-to-speech'
ELEVENLABS_VOICE_CLONE_URL = 'https://api.elevenlabs.io/v1/voice-clone'

def elevenlabs_tts(text, elevenlabs_voice_id):
    headers = {
        "Accept": "application/json",
        "xi-api-key": ELEVENLABS_API_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "text": text,
        "voice_id": elevenlabs_voice_id,
        "model_id": "eleven_monolingual_v1"
    }
    response = requests.post(ELEVENLABS_TTS_URL, json=data, headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result.get("audio_url", "")
    else:
        raise Exception("Elevenlabs TTS conversion failed.")

def elevenlabs_voice_clone(source_url):
    """
    Call Elevenlabs API to clone a voice from a provided file URL or link.
    Returns a tuple of (cloned_voice_id, sample_audio_url)
    """
    headers = {
        "xi-api-key": ELEVENLABS_API_KEY,
    }
    data = {
        "voice_file_url": source_url,
    }
    response = requests.post(ELEVENLABS_VOICE_CLONE_URL, json=data, headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result.get("cloned_voice_id", ""), result.get("sample_audio_url", "")
    else:
        raise Exception("Elevenlabs voice cloning failed.")

# --- Updated Voice Cloning Endpoint ---
class VoiceCloneView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    