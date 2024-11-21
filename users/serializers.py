from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from phonenumber_field.serializerfields import PhoneNumberField


User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom token serializer with email and phone verification."""
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        token['email_verified'] = user.email_verified
        token['phone_verified'] = user.phone_verified  
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        if not self.user.email_verified:
            raise serializers.ValidationError(
                {'email': _('Please verify your email address before logging in.')}
            )
        if not self.user.phone_verified:
            raise serializers.ValidationError(
                {'phone': _('Please verify your phone number before logging in.')}
            )
        data['email'] = self.user.email
        data['id'] = str(self.user.id)
        return data

class UserSerializer(serializers.ModelSerializer):
    """Serializer for user model."""
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'date_joined', 'last_login')
        read_only_fields = ('id', 'date_joined', 'last_login')

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating a new user."""
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True, required=True)
    phone_number = PhoneNumberField(required=True)
    phone_number_confirm = PhoneNumberField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm', 'first_name', 'last_name', 'phone_number', 'phone_number_confirm')

    def validate(self, attrs: dict) -> dict:
        """Validate password and phone number confirmation matches."""
        if attrs['password'] != attrs.pop('password_confirm'):
            raise serializers.ValidationError(
                {'password_confirm': _("Password fields didn't match.")}
            )
        if attrs['phone_number'] != attrs.pop('phone_number_confirm'):
            raise serializers.ValidationError(
                {'phone_number_confirm': _("Phone number fields didn't match.")}
            )
        return attrs

    def create(self, validated_data: dict) -> User:
        """Create and return a new user."""
        validated_data.pop('phone_number_confirm', None)  
        user = User.objects.create_user(**validated_data)
        return user
