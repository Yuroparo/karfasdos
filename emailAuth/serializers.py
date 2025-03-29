from rest_framework import serializers
from .models import Voice, TTSConversion, UserHistory, Payment
import os
from .models import UserHistory




class VoiceSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField()

    class Meta:
        model = Voice
        fields = ['id', 'name', 'avatar_path', 'sample_audio', 'elevenlabs_voice_id', 'is_public', 'created_at']

    def get_id(self, obj):
        # Return the id as a string
        return str(obj.id)



class TTSConversionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TTSConversion
        fields = ['id', 'text', 'voice', 'cost', 'audio_url', 'created_at']

class TopUpSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)




class UserHistorySerializer(serializers.ModelSerializer):
    title = serializers.SerializerMethodField()
    audio_url = serializers.SerializerMethodField()

    class Meta:
        model = UserHistory
        fields = ['id', 'action', 'title', 'audio_url', 'created_at']

    def get_title(self, obj):
        # Return the stored random title if available, otherwise fallback to the media file name.
        if obj.title:
            return obj.title
        if obj.media and obj.media.name:
            return obj.media.name.split('/')[-1]
        return "No Title"
    def get_audio_url(self, obj):
        request = self.context.get('request')
        if obj.media:
            return request.build_absolute_uri(obj.media.url) if request else obj.media.url
        return ""




class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['id', 'method', 'amount', 'currency', 'status', 'transaction_id', 'created_at', 'updated_at']
