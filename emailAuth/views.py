import requests
from decimal import Decimal
from django.db.models import Q
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Voice, TTSConversion, User, UserHistory, Payment
from .serializers import (VoiceSerializer, TTSConversionSerializer, TopUpSerializer, UserHistorySerializer, PaymentSerializer)
from django.core.mail import send_mail
from django.conf import settings
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import User
from django.contrib import admin
from rest_framework.authtoken.models import Token
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
import os
from django.contrib.auth import get_user_model
import uuid
from django.db import transaction
import random
from elevenlabs import ElevenLabs
from .services import create_virtual_account, get_elevenlabs_voices, voice_to_dict
from elevenlabs import ElevenLabs
import logging
from django.shortcuts import render
import json
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.template.loader import render_to_string

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

User = get_user_model()
password_reset_token_generator = PasswordResetTokenGenerator()

logger = logging.getLogger(__name__)





User = get_user_model()




# --- Email Verification (unchanged) ---



# Initialize a signer for email verification tokens.
signer = TimestampSigner()
# Initialize Django's password reset token generator.
password_reset_token_generator = PasswordResetTokenGenerator()

# Endpoint to send a verification email link.
# class SendEmailVerificationLinkView(APIView):
#     permission_classes = [permissions.IsAuthenticated]
    
#     def post(self, request):
#         user = request.user
#         # Generate a token that includes the user’s pk. This token expires in 1 day (86400 seconds).
#         token = signer.sign(user.pk)
#         verification_link = f"{settings.FRONTEND_URL}/verify-email/?token={token}"
        
#         send_mail(
#             'Verify Your Email Address',
#             f'Please click the following link to verify your email address: {verification_link}',
#             settings.DEFAULT_FROM_EMAIL,
#             [user.email],
#             fail_silently=False,
#         )
#         return Response({"message": "Verification link sent."}, status=status.HTTP_200_OK)


class SendEmailVerificationLinkView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        # Generate a token that includes the user’s pk. This token expires in 1 day (86400 seconds).
        token = signer.sign(user.pk)
        verification_link = f"{settings.FRONTEND_URL}/verify-email/?token={token}"
        
        # Render the HTML email template with the verification link
        html_message = render_to_string('verification_email.html', {'verification_link': verification_link})
        
        send_mail(
            'Verify Your Email Address',
            f'Please click the following link to verify your email address: {verification_link}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return Response({"message": "Verification link sent."}, status=status.HTTP_200_OK)


# Endpoint to verify the user's email address using the token.
class VerifyEmailView(APIView):
    def get(self, request):
        token = request.query_params.get('token')
        if not token:
            return Response({"error": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Unsign the token (valid for 1 day).
            user_pk = signer.unsign(token, max_age=86400)
            user = User.objects.get(pk=user_pk)
            # Here, you might set a flag such as user.email_verified = True.
            user.is_active = True  # Example: mark as verified
            user.save()
            return Response({"message": "Email verified."}, status=status.HTTP_200_OK)
        except SignatureExpired:
            return Response({"error": "Token expired."}, status=status.HTTP_400_BAD_REQUEST)
        except BadSignature:
            return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_400_BAD_REQUEST)

# Endpoint to send a password reset link to the user's email.

class SendPasswordResetLinkView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "No user found with that email."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create uid and token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = password_reset_token_generator.make_token(user)
        
        # Construct the reset link that points to your changepassword.html page
        # For example, if your frontend is hosted at settings.FRONTEND_URL:
        reset_link = f"{settings.FRONTEND_URL}/change-password/?uid={uid}&token={token}"
        
        # Render the HTML email template with the reset link
        html_message = render_to_string('password_reset_email.html', {'reset_link': reset_link})
        
        send_mail(
            'Reset Your Password',
            f'Please click the following link to reset your password: {reset_link}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        return Response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)




# Endpoint to confirm the password reset using the uid and token.
class ResetPasswordConfirmView(APIView):
    def post(self, request):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")
        
        if not uidb64 or not token or not new_password:
            return Response({"error": "uid, token, and new_password are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)
        
        if password_reset_token_generator.check_token(user, token):
            user.password = make_password(new_password)
            user.save()
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)






class EmailVerificationReminderView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        action = request.data.get("action")  # "send_link" or "remind_later"
        if action == "send_link":
            print(f"Sending verification email to {user.email}")
            return Response({"message": "Verification link sent."}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "Reminder set."}, status=status.HTTP_200_OK)



# --- Top Up Balance (for manual topup via other methods) ---
class TopUpBalanceView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = TopUpSerializer(data=request.data)
        if serializer.is_valid():
            amount = serializer.validated_data["amount"]
            user = request.user
            user.balance += amount
            user.save()
            return Response({"balance": f"{user.balance:.2f}"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    



# --- User History ---




class UserHistoryListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        history = UserHistory.objects.filter(user=user).order_by('-created_at')
        serializer = UserHistorySerializer(history, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    def post(self, request):
            # """
            # Expects a file upload (audio/video) under key 'file'.
            # The file is stored in the media field and a random title (e.g., "Audio 1234")
            # is generated and saved for display.
            # """
        if 'file' not in request.FILES:
            return Response({"error": "File is required."}, status=status.HTTP_400_BAD_REQUEST)

        file_obj = request.FILES['file']

    # Validate that the file is an audio or video file.
        valid_audio = ['audio/mpeg', 'audio/mp3', 'audio/wav']
        valid_video = ['video/mp4', 'video/x-matroska', 'video/quicktime']
        if file_obj.content_type not in (valid_audio + valid_video):
            return Response({"error": "Only audio/video files are allowed."}, status=status.HTTP_400_BAD_REQUEST)

    # Generate a random title for display, e.g., "Audio 1234"
        random_title = f"Record {random.randint(1000, 9999)}"

    # Create the history record.
        history = UserHistory.objects.create(
            user=request.user,
            action='tts',  # or 'clone' depending on context
            title=random_title,
        )
    # Save the uploaded file directly to the history's media field.
        history.media.save(file_obj.name, file_obj)

        serializer = UserHistorySerializer(history, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)


    



# --- Payment Initiation ---



class PaymentInitiateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        payment_method = request.data.get("payment_method")
        amount = Decimal(request.data.get("amount", "0"))
        
        # Generate a unique transaction reference.
        reference = f"{payment_method.upper()}-{user.id}-{uuid.uuid4().hex[:8]}"
        tx_ref = f"VA-{user.id}-{uuid.uuid4().hex[:8]}"

        
        if payment_method == 'flutterwave':
            # Flutterwave: minimum card payment e.g., 2000 NGN.
            if amount < Decimal("2000"):
                return Response({"error": "Minimum card payment is 2000 NGN."}, status=status.HTTP_400_BAD_REQUEST)
            
            payload = {
                "narration": "Dotclone",
                "tx_ref": reference,
                "amount": str(amount),
                "currency": "NGN",
               # "redirect_url": "[YOUR_REDIRECT_URL]",  # Replace with your redirect URL
                "customer": {
                    "email": user.email,
                    "name": user.username,
                },
                "customizations": {
                    "title": "Top Up Balance",
                    "description": "Payment to top up your balance",
                }
            }
            # payload = {
            #     "email": user.email,
            #     "currency": "NGN",
            #      "amount": 2000,
            #      "tx_ref": tx_ref,
            #     "is_permanent": False,
            #     "narration": "Dotclone"  # Fixed narration and account name
            # }
    
            
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer ", # Replace with your Flutterwave secret key
            }
            flutterwave_endpoint = "https://api.flutterwave.com/v3/payments"
            flutterwave_response = requests.post(flutterwave_endpoint, json=payload, headers=headers)
            if flutterwave_response.status_code == 200:
                res_data = flutterwave_response.json()
                payment_link = res_data["data"]["link"]
                payment = Payment.objects.create(
                    user=user,
                    method='flutterwave',
                    amount=amount,
                    currency='NGN',
                    transaction_id=reference,
                    status='pending'
                )
                serializer = PaymentSerializer(payment)
                return Response({
                    "payment_link": payment_link,
                    "reference": reference,
                    "payment": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to initiate Flutterwave payment.",
                    "details": flutterwave_response.text
                }, status=status.HTTP_400_BAD_REQUEST)
        
        elif payment_method == 'btcpay':
            # BTCPayServer: minimum BTC payment, for example 0.001 BTC (adjust as needed).
            if amount < Decimal("0.001"):
                return Response({"error": "Minimum BTC payment is 0.001 BTC."}, status=status.HTTP_400_BAD_REQUEST)
            
            payload = {
                "price": str(amount),  # Amount in BTC
                "currency": "BTC",
                "orderId": reference,
                "itemDesc": "Top Up Balance",
                # Additional fields per BTCPayServer API docs.
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Basic  6cccec15e0a1688959bdec4e3edca5328de0659f"  # Replace with your BTCPay API key
            }
            btcpay_endpoint = "http://192.168.145.229:8000/payments/btcpay/details/api/v1/invoices"  # Replace with your BTCPayServer URL
            btcpay_response = requests.post(btcpay_endpoint, json=payload, headers=headers)
            if btcpay_response.status_code == 200:
                res_data = btcpay_response.json().get("data", {})
                wallet_address = res_data.get("walletAddress") or res_data.get("address") or "N/A"
                qr_code_url = res_data.get("qrCodeUrl") or "N/A"
                payment = Payment.objects.create(
                    user=user,
                    method='btcpay',
                    amount=amount,
                    currency='BTC',
                    transaction_id=reference,
                    status='pending'
                )
                serializer = PaymentSerializer(payment)
                return Response({
                    "wallet_address": wallet_address,
                    "qr_code_url": qr_code_url,
                    "reference": reference,
                    "payment": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to initiate BTCPayServer payment.",
                    "details": btcpay_response.text
                }, status=status.HTTP_400_BAD_REQUEST)
        
        elif payment_method == 'usdt':
            # USDT via CoinGate: assume minimum is, e.g., 10 USDT (adjust as needed).
            if amount < Decimal("10"):
                return Response({"error": "Minimum USDT payment is 10 USDT."}, status=status.HTTP_400_BAD_REQUEST)
            
            reference = f"USDT-{user.id}-{uuid.uuid4().hex[:8]}"
            payload = {
                "price": str(amount),  # Price in USDT
                "currency": "USDT",
                "order_id": reference,
                "item_description": "Top Up Balance",
                # Additional fields as required by CoinGate's API.
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Basic [YOUR_COINGATE_API_KEY]"  # Replace with your CoinGate API key
            }
            # Replace with your actual CoinGate server URL endpoint for creating orders/invoices.
            coingate_endpoint = "[YOUR_COINGATE_SERVER_URL]/v2/orders"  
            coingate_response = requests.post(coingate_endpoint, json=payload, headers=headers)
            if coingate_response.status_code == 200:
                res_data = coingate_response.json().get("data", {})
                wallet_address = res_data.get("walletAddress") or res_data.get("address") or "N/A"
                qr_code_url = res_data.get("qrCodeUrl") or "N/A"
                payment = Payment.objects.create(
                    user=user,
                    method='usdt',
                    amount=amount,
                    currency='USDT',
                    transaction_id=reference,
                    status='pending'
                )
                serializer = PaymentSerializer(payment)
                return Response({
                    "wallet_address": wallet_address,
                    "qr_code_url": qr_code_url,
                    "reference": reference,
                    "payment": serializer.data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "error": "Failed to initiate USDT payment via CoinGate.",
                    "details": coingate_response.text
                }, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            return Response({"error": "Invalid payment method."}, status=status.HTTP_400_BAD_REQUEST)

# --- Payment Webhook ---


class PaymentWebhookView(APIView):
    # It’s important to secure this endpoint by verifying any provided signatures.
    def post(self, request):
        # Extract the transaction reference, status, and amount from the request.
        # Adjust these keys based on Flutterwave’s webhook payload structure.
        tx_ref = request.data.get("tx_ref")
        status_update = request.data.get("status")  # e.g., "successful" or "failed"
        amount = request.data.get("amount")  # Expected to be a string or numeric

        # For debugging, log the payload.
        print("Webhook received:", request.data)

        if not tx_ref or not status_update or amount is None:
            return Response({"error": "Invalid payload"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the payment record based on the transaction reference.
            payment = Payment.objects.get(transaction_id=tx_ref)
        except Payment.DoesNotExist:
            return Response({"error": "Payment record not found."}, status=status.HTTP_404_NOT_FOUND)

        # Update the payment status.
        payment.status = status_update
        payment.save()

        # Only update the user's balance if the payment is marked as successful.
        if status_update.lower() == 'successful':
            try:
                # Ensure amount is converted to Decimal.
                amount_decimal = Decimal(amount)
            except Exception as e:
                return Response({"error": f"Invalid amount format: {e}"}, status=status.HTTP_400_BAD_REQUEST)
            user = payment.user
            user.balance += amount_decimal
            user.save()
            print(f"User {user.username} balance updated: {user.balance}")

        return Response({"message": "Payment processed successfully."}, status=status.HTTP_200_OK)

# --- Authentication Endpoints ---


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]  # Allow unauthenticated access

    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        if not username or not email or not password:
            return Response(
                {"error": "username, email and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
            return Response(
                {"error": "Username/email exist"},
                status=status.HTTP_400_BAD_REQUEST
            )
        user = User.objects.create(
            username=username,
            email=email,
            password=make_password(password)
        )
        token, created = Token.objects.get_or_create(user=user)
        
        # Create a virtual account for the user using Flutterwave
        try:
            account_number, bank_name, account_name = create_virtual_account(user)
            user.flutterwave_account_number = account_number
            user.flutterwave_bank_name = bank_name
            user.flutterwave_account_name = account_name
            user.save()
        except Exception as e:
            print("Error creating virtual account:", e)
            # Optionally, you may decide to return an error response or continue.
        
        return Response(
            {
                "token": token.key,
                "message": "User registered successfully. Please verify your email later.",
                "virtual_account": {
                    "account_number": user.flutterwave_account_number,
                    "bank_name": user.flutterwave_bank_name,
                    "account_name": user.flutterwave_account_name,
                }
            },
            status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny] 
    # Allow unauthenticated access
    
    def post(self, request):
        identifier = request.data.get("identifier")  # email or username
        password = request.data.get("password")
        if not identifier or not password:
            return Response({"error": "identifier and password are required."}, status=status.HTTP_400_BAD_REQUEST)
        user = None
        if "@" in identifier:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                pass
        else:
            try:
                user = User.objects.get(username=identifier)
            except User.DoesNotExist:
                pass
        if user:
            user = authenticate(username=user.username, password=password)
            if user:
                token, _ = Token.objects.get_or_create(user=user)
                return Response({"token": token.key}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)



class ResetPasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        new_password = request.data.get("new_password")
        if not new_password:
            return Response({"error": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)
        user = request.user
        user.password = make_password(new_password)
        user.save()
        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)

class GoogleAuthView(APIView):
    def post(self, request):
        google_token = request.data.get("google_token")
        if not google_token:
            return Response({"error": "Google token is required."}, status=status.HTTP_400_BAD_REQUEST)
        # In production, verify the token with Google's API.
        email = request.data.get("email")
        username = request.data.get("username") or email.split("@")[0]
        if not email:
            return Response({"error": "Email is required from Google token."}, status=status.HTTP_400_BAD_REQUEST)
        user, created = User.objects.get_or_create(email=email, defaults={
            "username": username,
            "password": make_password(User.objects.make_random_password()),
        })
        from rest_framework.authtoken.models import Token
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "message": "Logged in with Google."}, status=status.HTTP_200_OK)


class BalanceView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        return Response({"balance": str(request.user.balance)}, status=status.HTTP_200_OK)
    

class UserHistoryDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        try:
            history_item = UserHistory.objects.get(pk=pk, user=request.user)
        except UserHistory.DoesNotExist:
            return Response({"error": "History item not found."}, status=status.HTTP_404_NOT_FOUND)
        history_item.delete()
        return Response({"message": "History item deleted successfully."}, status=status.HTTP_200_OK)
    

# TTSConversion



# PaymentDetailsView

class PaymentDetailsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        data = {
            "account_number": user.flutterwave_account_number,
            "bank_name": user.flutterwave_bank_name,
            "account_name": user.flutterwave_account_name,
        }
        return Response(data, status=status.HTTP_200_OK)
    

# --- Voice List (Global Voices: Only voices marked as public) ---

class VoiceListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        # Return only voices marked as public.
        voices = Voice.objects.filter(is_public=True)
        serializer = VoiceSerializer(voices, many=True)
        return Response({"voices": serializer.data}, status=status.HTTP_200_OK)

# --- User Voices (Only voices created by the current user) ---


class SampleVoicesView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        user = request.user
        # Return voices that are either created by the user or marked as public.
        voices = Voice.objects.filter(Q(user=user) | Q(is_public=True))
        serializer = VoiceSerializer(voices, many=True)
        return Response({"voices": serializer.data}, status=status.HTTP_200_OK)


# --- Voice Cloning ---
class VoiceCloneView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        if user.balance < Decimal('500'):
            return Response(
                {"error": "Insufficient balance. You need at least 500 to add a new voice."},
                status=status.HTTP_400_BAD_REQUEST
            )
        logger.info("Voice cloning request received from user: %s", user.username)
        logger.debug("Request data: %s", request.data)
        
        if 'file' not in request.FILES:
            logger.error("No file provided in the request.")
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        file_obj = request.FILES['file']
        logger.info("File found in request: %s", file_obj.name)
        
        file_bytes = file_obj.read()
        saved_file_path = default_storage.save(f"voice_uploads/{file_obj.name}", ContentFile(file_bytes))
        logger.info("File saved to storage as: %s", saved_file_path)
        
        try:
            full_file_path = default_storage.path(saved_file_path)
            logger.info("Full file system path: %s", full_file_path)
        except Exception as e:
            logger.error("Error obtaining absolute path for saved file: %s", e, exc_info=True)
            return Response({"error": "Error processing file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        voice_name = request.data.get("name")
        if not voice_name:
            logger.error("Voice name is missing in the request.")
            return Response({"error": "Voice name is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        avatar_path = request.data.get("avatar_path", "")
        # Read the is_public parameter if provided (for user-created voices, default remains False)
        # Typically, voices created by users default to private; an admin would later mark them public.
        is_public_param = request.data.get("is_public", "false").lower() in ["true", "1"]
        
        try:
            client = ElevenLabs(api_key='')
            with default_storage.open(saved_file_path, 'rb') as f:
                result = client.voices.add(
                    name=voice_name,
                    files=[f],
                )
            logger.debug("ElevenLabs voices.add response: %s", result)
            
            cloned_voice_id = result.voice_id
            sample_audio_url = getattr(result, "sample_audio_url", None)
            
            if not cloned_voice_id:
                logger.error("API call succeeded but missing voice_id in response: %s", result)
                return Response({"error": "Voice cloning failed: missing voice id."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            if not sample_audio_url:
                logger.info("No preview audio returned; generating preview audio.")
                preview_response = client.generate(
                    text="This is a preview of the cloned voice.",
                    voice=cloned_voice_id,
                    model="eleven_turbo_v2"
                )
                sample_audio_url = getattr(preview_response, "sample_audio_url", None)
                logger.debug("Preview generated: %s", sample_audio_url)
                
        except Exception as e:
            logger.error("Exception during voice cloning: %s", e, exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            # Create the Voice record.
            # so they don't show globally unless an admin updates it.
            new_voice = Voice.objects.create(
                user=user,
                name=voice_name,
                avatar_path=avatar_path,
                sample_audio=sample_audio_url,
                elevenlabs_voice_id=cloned_voice_id,
                is_public=is_public_param  # This can be updated via admin.
            )
            logger.info("New voice created with id: %s", new_voice.id)
            UserHistory.objects.create(user=user, action="clone", title=voice_name)
            logger.info("User history updated for cloning action.")
        except Exception as e:
            logger.error("Error saving voice to database: %s", e, exc_info=True)
            return Response({"error": "Failed to save voice to database."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        serializer = VoiceSerializer(new_voice)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    



class TTSConversionView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @transaction.atomic
    def post(self, request):
        user = request.user
        text = request.data.get("text", "")
        voice_id = request.data.get("voice_id")  # selected voice from the frontend

        if not text:
            return Response({"error": "Text is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Calculate cost (2 per character, with a minimum charge)
        cost = Decimal(2 * len(text))
        minimum_charge = Decimal("2.00")
        if cost < minimum_charge:
            return Response({
                "error": "Text too short.",
                "cost": f"{cost:.2f}",
                "minimum_charge": f"{minimum_charge:.2f}"
            }, status=status.HTTP_400_BAD_REQUEST)

        if user.balance < cost:
            shortage = cost - user.balance
            return Response({
                "error": "Insufficient balance.",
                "required_topup": f"{shortage:.2f}"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Deduct the cost from the user's balance.
        user.balance -= cost
        user.save()

        # Retrieve the voice.
        if voice_id:
            try:
                voice_instance = Voice.objects.get(id=voice_id, user=user)
            except Voice.DoesNotExist:
                return Response({"error": "Voice not found."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            voice_instance = Voice.objects.filter(user=user).first()
            if not voice_instance:
                return Response({"error": "No voice available. Please create a voice first."},
                                status=status.HTTP_400_BAD_REQUEST)

        elevenlabs_voice_id = voice_instance.elevenlabs_voice_id

        try:
            client = ElevenLabs(api_key='')
            conversion_result = client.generate(
                text=text,
                voice=elevenlabs_voice_id,
                model="eleven_multilingual_v2",
                output_format="mp3_44100_128"
            )
            # Ensure we always obtain audio_bytes.
            audio_bytes = None
            if isinstance(conversion_result, bytes):
                audio_bytes = conversion_result
            elif hasattr(conversion_result, '__iter__'):
                audio_bytes = b"".join(chunk for chunk in conversion_result)
            else:
                # Assume conversion_result is a URL; download the file to obtain audio_bytes.
                audio_url_temp = conversion_result
                response = requests.get(audio_url_temp)
                if response.status_code == 200:
                    audio_bytes = response.content
                else:
                    raise Exception("Could not retrieve audio data from URL.")

            if audio_bytes is None:
                raise Exception("Audio data is missing.")

            # Always save the audio bytes to local storage to get a file path and absolute URL.
            file_name = f"tts_audio_{uuid.uuid4().hex}.mp3"
            file_path = default_storage.save(f"tts/{file_name}", ContentFile(audio_bytes))
            audio_url = request.build_absolute_uri(default_storage.url(file_path))
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Generate a random title for display.
        generated_title = f"Audio {random.randint(1000, 9999)}"

        # Create a conversion record.
        tts_conversion = TTSConversion.objects.create(
            user=user,
            text=generated_title,  # Optionally store the original text if needed
            voice=voice_instance,
            cost=cost,
            audio_url=audio_url
        )
        
        # Create a user history record and attach the audio file to its FileField.
        history = UserHistory.objects.create(
            user=user,
            action="tts",
            title=generated_title,
        )
        history.media.save(os.path.basename(file_path), ContentFile(audio_bytes))

        serializer = TTSConversionSerializer(tts_conversion)
        user.refresh_from_db()

        return Response({
            "conversion": serializer.data,
            "new_balance": f"{user.balance:.2f}"
        }, status=status.HTTP_200_OK)



from django.shortcuts import render

def custom_404_view(request, exception):
    context = {'error_message': "The page you requested was not found."}
    return render(request, '404.html', context, status=404)



class ResetPasswordConfirmApiView(APIView):
    """
    API endpoint that resets a user's password.
    Expects the uid and token as part of the URL and a JSON payload containing "password".
    Only non-superusers are allowed to reset their password here.
    """
    def post(self, request, uidb64, token):
        new_password = request.data.get("password")
        if not new_password:
            return Response({"error": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Only allow password resets for non-superusers.
        if user.is_superuser:
            return Response({"error": "Superusers cannot reset their password using this endpoint."},
                            status=status.HTTP_403_FORBIDDEN)
        
        if password_reset_token_generator.check_token(user, token):
            user.password = make_password(new_password)
            user.save()
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
