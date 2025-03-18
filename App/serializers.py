from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth import  authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import TeamUser, Team, TeamMembership, Task
from django.core.files.base import ContentFile
import base64
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

# Registration Authentication
# Serializer for user registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, min_length=8)  # Primary password
    password2 = serializers.CharField(write_only=True, required=True)  # Confirm password
    profile_picture = serializers.ImageField(required=False, allow_null=True, allow_empty_file=True)  # Optional profile picture
    class Meta:
        model = TeamUser
        fields = ['id', 'email', 'username', 'password', 'password2', 'role', 'profile_picture', 'bio']  # Fields exposed by the serializer
        extra_kwargs = {
            'role': {'required': True}  # Role is required for user registration
        }

    def validate(self, data):
        # Ensure passwords match
        if data['password'] != data['password2']:
            raise serializers.ValidationError('Passwords do not match.')
        # Ensure the role is valid
        role = data.get('role')
        if role not in dict(TeamUser.ROLE_CHOICES):
            raise serializers.ValidationError({
                'role': f'Invalid role. Choose from {", ".join([role[0] for role in TeamUser.ROLE_CHOICES])}'
            })
        # Handle empty profile picture
        if 'profile_picture' in data and data['profile_picture'] == "":
            data['profile_picture'] = None
        return data

    def create(self, validated_data):
        """
        Creates a new TeamUser instance with the validated data.
        """
        validated_data.pop('password2', None)  # Remove the confirm password from the data
        role = validated_data.pop('role')  # Extract the role
        profile_picture = validated_data.pop('profile_picture', None)  # Extract the profile picture if provided
        bio = validated_data.pop('bio', None)  # Extract the bio if provided
        # Create the user with the validated data
        user = TeamUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        # Assign additional fields to the user
        user.role = role
        if bio:
            user.bio = bio
        if profile_picture:
            user.profile_picture = profile_picture
        user.save()  # Save the user instance to the database
        return user

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for handling login requests.
    """
    email = serializers.EmailField(required=True)  # User email
    password = serializers.CharField(write_only=True, required=True)  # Password (not included in response)

    def validate(self, data):
        """
        Validate email and password, authenticate user, and generate tokens.
        """
        # Authenticate the user using the email and password
        user = authenticate(email=data['email'], password=data['password'])
        
        if not user:
            # Raise error if authentication fails
            raise serializers.ValidationError({
                'error': "Invalid email or password."
            })
        
        if not user.is_active:
            # Raise error if the user's account is disabled
            raise serializers.ValidationError("This account is disabled.")

        # Generate refresh and access tokens for the authenticated user
        refresh = RefreshToken.for_user(user)
        
        # Return user details and tokens
        return {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'bio': user.bio,
                'profile_picture': user.profile_picture.url if user.profile_picture else None
            },
            'refresh': str(refresh),  # Refresh token as a string
            'access': str(refresh.access_token),  # Access token as a string
        }

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeamUser
        fields = '__all__'
# Team management serializer 
class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = '__all__'

class TeamMembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = TeamMembership
        fields = ['user', 'team']  # Removed 'role'

    def validate_user(self, value):
        if not TeamUser.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Invalid user_id")
        return value

    def validate_team(self, value):
        if not Team.objects.filter(id=value.id).exists():
            raise serializers.ValidationError("Invalid team_id")
        return value


# Task management serializer
class TaskSerializer(serializers.ModelSerializer):
    assigned_to_team = TeamSerializer(read_only=True)
    assigned_to_user = UserSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    # Write-only fields for handling assignments during creation/update
    assigned_to_team_id = serializers.PrimaryKeyRelatedField(
        queryset=Team.objects.all(), write_only=True, allow_null=True, required=False, source='assigned_to_team'
    )
    assigned_to_user_id = serializers.PrimaryKeyRelatedField(
        queryset=TeamUser.objects.all(), write_only=True, allow_null=True, required=False, source='assigned_to_user'
    )

    class Meta:
        model = Task
        fields = [
            'id', 'title', 'description', 'priority', 'deadline',
            'status', 'status_display', 'assigned_type', 'assigned_to_team', 'assigned_to_user',
            'assigned_to_team_id', 'assigned_to_user_id', 'created_by', 'created_at', 'updated_at', 'is_overdue'
        ]
        read_only_fields = ['created_at', 'updated_at', 'created_by']

    def validate(self, data):
        assigned_type = data.get("assigned_type")
        assigned_to_team = data.get("assigned_to_team")
        assigned_to_user = data.get("assigned_to_user")

        logger.info(f"Validating data: {data}")

        if assigned_type == "TEAM" and not assigned_to_team:
            logger.error("A team must be assigned when assigned_type is TEAM.")
            raise serializers.ValidationError({"assigned_to_team_id": "A team must be assigned when assigned_type is TEAM."})

        if assigned_type == "USER" and not assigned_to_user:
            logger.error("A user must be assigned when assigned_type is USER.")
            raise serializers.ValidationError({"assigned_to_user_id": "A user must be assigned when assigned_type is USER."})

        # Ensure only one of assigned_to_team or assigned_to_user is set
        if assigned_to_team and assigned_to_user:
            logger.error("A task cannot be assigned to both a team and a user.")
            raise serializers.ValidationError("A task cannot be assigned to both a team and a user.")

        return data

    def validate_deadline(self, value):
        if value and value < timezone.now():
            logger.error("Deadline cannot be in the past")
            raise serializers.ValidationError("Deadline cannot be in the past")
        return value