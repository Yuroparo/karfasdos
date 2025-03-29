import requests
import uuid
from elevenlabs import ElevenLabs
from django.conf import settings
import json
import logging
from django.conf import settings
from elevenlabs import ElevenLabs
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from django.http import FileResponse, Http404

logger = logging.getLogger(__name__)


def create_virtual_account(user):
    url = "https://api.flutterwave.com/v3/virtual-account-numbers"
    tx_ref = f"VA-{user.id}-{uuid.uuid4().hex[:8]}"
    payload = {
        "email": user.email,
        "currency": "NGN",
        "amount": 2000,
        "tx_ref": tx_ref,
        "is_permanent": False,
        "narration": "Dotclone"  # Fixed narration and account name
    }
    headers = {
        "accept": "application/json",
        "Authorization": "Bearer ",
        "Content-Type": "application/json"
    }
    
    response = requests.post(url, json=payload, headers=headers)
    print("Full Flutterwave Response:", response.text)  # Debug output
    if response.status_code == 200:
        data = response.json().get("data", {})
        account_number = data.get("account_number")
        # Try to extract bank name from a nested structure or directly.
        bank_info = data.get("bank")
        if bank_info and isinstance(bank_info, dict):
            bank_name = bank_info.get("name")
        else:
            bank_name = data.get("bank_name")  # Fallback if not nested.
        # Set account name to "Dotclone" as requested.
        account_name = "Dotclone"
        return account_number, bank_name or "N/A", account_name
    else:
        raise Exception("Failed to create virtual account: " + response.text)



logger = logging.getLogger(__name__)


def get_elevenlabs_voices():
    """
    Fetch voices from ElevenLabs. If the client returns a tuple or an object
    with a voices attribute, extract the list of voices.
    """
    try:
        client = ElevenLabs(
            # xi_api_key=settings.ELEVENLABS.get('XI_API_KEY'),
            api_key=settings.ELEVENLABS.get('API_KEY')
        )
        result = client.voices.get_all(show_legacy=False)

        # If result is a tuple like ("voices", [...]), extract the second element.
        if isinstance(result, tuple) and len(result) == 2 and result[0] == "voices":
            voices = result[1]
        # If result is an object with a 'voices' attribute, use that attribute.
        elif hasattr(result, "voices"):
            voices = result.voices
        else:
            voices = result

        logger.info("Fetched %d voices", len(voices))
        return voices
    except Exception as e:
        logger.error("Error fetching voices: %s", e, exc_info=True)
        raise


def voice_to_dict(voice):
    """
    Convert a Voice object or dict to a JSON-serializable dictionary.
    """
    if isinstance(voice, dict):
        voice_id = voice.get("voice_id") or voice.get("id")
        name = voice.get("name")
        preview_url = voice.get("preview_url")
        description = voice.get("description")
        # Check if there's a nested label for description if description is missing
        if not description and isinstance(voice.get("labels"), dict):
            description = voice.get("labels", {}).get("description")
    else:
        voice_id = getattr(voice, "voice_id", None)
        name = getattr(voice, "name", None)
        preview_url = getattr(voice, "preview_url", None)
        description = getattr(voice, "description", None)
        if not description and hasattr(voice, "labels") and isinstance(voice.labels, dict):
            description = voice.labels.get("description")
    
    return {
        "id": voice_id,
        "name": name,
        "preview_url": preview_url,
        "description": description
    }




def download_audio(request, file_path):
    try:
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = 'attachment; filename="audio.mp3"'
        return response
    except FileNotFoundError:
        raise Http404("Audio file not found")
