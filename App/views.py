from django.shortcuts import render,redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .permission import IsTeamAdmin, IsTeamMember
from django.contrib.auth import authenticate
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from .models import *
from .serializers import TeamSerializer, TeamMembershipSerializer, TaskSerializer, UserSerializer
from rest_framework.decorators import api_view, action
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, filters
from django.utils import timezone
import json
import time
from django.http import StreamingHttpResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.db.models import Count
from django.http import JsonResponse
from django.db.models.functions import TruncMonth
from django.core.serializers.json import DjangoJSONEncoder
import logging

# API view for user registration
class UserRegistrationView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated users to register

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)  # Deserialize incoming data
        if serializer.is_valid():  # Validate the data
            try:
                user = serializer.save()  # Save the user to the database
                refresh = RefreshToken.for_user(user)  # Generate JWT tokens for the user
                
                # Prepare profile picture URL if it exists
                profile_picture_url = None
                if user.profile_picture:
                    profile_picture_url = request.build_absolute_uri(user.profile_picture.url)

                # Return success response with user details and tokens
                return Response({
                    'message': 'User registered successfully',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role,
                        'bio': user.bio,
                        'profile_picture': profile_picture_url,
                    },
                    'tokens': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    },
                }, status=201)
            except Exception as e:
                # Handle any unexpected errors during user creation
                return Response({
                    'error': 'Registration failed',
                    'details': str(e)
                }, status=400)
        
        # If data is invalid, return the validation errors
        return Response({
            'error': 'Invalid data',
            'details': serializer.errors,
        }, status=400)
    

#  User login views
class UserLoginView(APIView):
    """
    Handles user login and token generation.
    """
    permission_classes = [AllowAny]  # Allow access to all users, even unauthenticated ones.

    def post(self, request):
        """
        Accepts email and password, authenticates user, and returns tokens if successful.
        """
        # Use a serializer to validate and process login data
        serializer = UserLoginSerializer(data=request.data)
        
        if serializer.is_valid():
            # Extract validated user data and tokens
            validated_data = serializer.validated_data
            
            # Return a success response with user info and tokens
            return Response({
                'message': 'Login successful',
                'user': validated_data['user'],
                'tokens': {
                    'refresh': validated_data['refresh'],  # Refresh token for renewing sessions
                    'access': validated_data['access'],    # Access token for authentication
                }
            }, status=status.HTTP_200_OK)

        # Return an error response if login fails
        return Response({
            'error': 'Login failed',
            'details': serializer.errors
        }, status=status.HTTP_401_UNAUTHORIZED)

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = TeamUser.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        user = request.user  # Get the currently logged-in user
        return Response({
            "username": user.username,
            "role": user.role,  # Assuming `role` is a field in your User model
            "profile_picture": user.profile_picture.url if user.profile_picture else None,
        })

    
# Team management setview
class TeamViewSet(ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [IsAuthenticated]


class TeamMembersView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, team_id):
        # Fetch all memberships for the given team ID
        memberships = TeamMembership.objects.filter(team_id=team_id)
        if not memberships.exists():
            return Response({'error': 'Team not found or no members'}, status=404)

        serializer = TeamMembershipSerializer(memberships, many=True)
        return Response(serializer.data, status=200)


# Adding/Removing Users to/from Teams
# Adding/Removing Users to/from Teams
class TeamMembershipView(APIView):
    permission_classes = [IsAuthenticated]

    # Assign a user to a team
    def post(self, request):
        team_id = request.data.get('team_id')
        user_id = request.data.get('user_id')

        # Validate required fields
        if not all([team_id, user_id]):
            return Response({'error': 'team_id and user_id are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate team existence
        if not Team.objects.filter(id=team_id).exists():
            return Response({'error': 'Invalid team_id'}, status=status.HTTP_404_NOT_FOUND)

        # Validate user existence
        if not TeamUser.objects.filter(id=user_id).exists():
            return Response({'error': 'Invalid user_id'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is already a member of the team
        if TeamMembership.objects.filter(user_id=user_id, team_id=team_id).exists():
            return Response({'message': 'User is already a member of this team'}, status=status.HTTP_200_OK)

        # Create the team membership
        try:
            team_user = TeamUser.objects.get(id=user_id)
            team = Team.objects.get(id=team_id)
            TeamMembership.objects.create(user=team_user, team=team)
            return Response({'message': 'User successfully assigned to the team'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Remove a user from a team
    def delete(self, request):
        user_id = request.data.get('user_id')
        team_id = request.data.get('team_id')

        # Validate membership existence
        membership = TeamMembership.objects.filter(user_id=user_id, team_id=team_id).first()
        if membership:
            membership.delete()
            return Response({'message': 'User removed from the team'}, status=status.HTTP_204_NO_CONTENT)

        return Response({'error': 'Membership not found'}, status=status.HTTP_404_NOT_FOUND)

    
    # removing user from team
    def delete(self, request):
        user_id = request.data.get('user_id')
        team_id = request.data.get('team_id')
        membership = TeamMembership.objects.filter(user_id=user_id, team_id= team_id).first()
        if membership:
            membership.delete()
            return Response({'message':'User removed from the team'}, status=status.HTTP_204_NO_CONTENT)
        return Response({'error':'Membership not found'}, status=status.HTTP_404_NOT_FOUND)
    
# Endpoint: Assigning roles to users
@api_view(['PUT'])
def assign_role(request):
    role = request.data.get('role')
    team_id = request.data.get('team_id')
    user_id = request.data.get('user_id')

    # Validate required fields
    if not all([role, team_id, user_id]):
        return Response({'error': 'role, team_id, and user_id are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        membership = TeamMembership.objects.get(user_id=user_id, team_id=team_id)
        membership.role = role
        membership.save()
        return Response({'message': 'Role updated successfully'}, status=status.HTTP_200_OK)
    except TeamMembership.DoesNotExist:
        return Response({'error': 'Membership not found'}, status=status.HTTP_404_NOT_FOUND)

    
# Task management viewset
class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'priority', 'assigned_type', 'assigned_to_team', 'assigned_to_user']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'deadline', 'priority']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        # Automatically set the created_by field to the current user
        serializer.save(created_by=self.request.user)

    @action(detail=False, methods=['get'])
    def my_tasks(self, request):
        # Filter tasks assigned to the current user or teams the user is a member of
        tasks = Task.objects.filter(
            Q(assigned_to_user=request.user) |
            Q(assigned_to_team__members=request.user)
        ).distinct()
        serializer = self.get_serializer(tasks, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def overdue(self, request):
        # Filter tasks that are overdue and not completed
        tasks = Task.objects.filter(
            deadline__lt=timezone.now(),
            status__in=['pending', 'in_progress', 'blocked']
        )
        serializer = self.get_serializer(tasks, many=True)
        return Response(serializer.data)    

# Real time notification views
logger = logging.getLogger(__name__)

def fetch_latest_data():
    tasks = Task.objects.order_by("-created_at")[:5].values('id', 'title', 'description', 'created_at')
    teams = Team.objects.order_by("-created_at")[:5].values('id', 'name', 'description', 'created_at')
    users = TeamUser.objects.order_by("-date_joined")[:5].values('id', 'email', 'role')

    data = {
        "tasks": list(tasks),
        "teams": list(teams),
        "users": list(users)
    }

    logger.info(f"Fetched latest data: {data}")
    return json.dumps(data, cls=DjangoJSONEncoder)

def event_stream():
    while True:
        data = fetch_latest_data()
        logger.info(f"Sending data: {data}")
        yield f"data: {data}\n\n"
        time.sleep(5)

def notifications_stream(request):
    token = request.GET.get("token")
    jwt_authenticator = JWTAuthentication()

    if not token:
        return StreamingHttpResponse(
            "data: {\"error\":\"Token Required\"}\n\n", 
            content_type="text/event-stream"
        )

    try:
        validated_token = jwt_authenticator.get_validated_token(token)
        user = jwt_authenticator.get_user(validated_token)

        if not isinstance(user, TeamUser):
            return StreamingHttpResponse(
                "data: {\"error\":\"Invalid User\"}\n\n", 
                content_type="text/event-stream"
            )
        
    except Exception as e:
        return StreamingHttpResponse(
            f"data: {{\"error\": \"{str(e)}\"}}\n\n", 
            content_type="text/event-stream"
        )

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


 
# Data visualization
@api_view(['GET'])
def task_status_chart(request):
    try:
        status_counts = Task.objects.values('status').annotate(count=Count('status'))
        return JsonResponse(list(status_counts), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['GET'])
def task_priority_chart(request):
    try:
        priority_counts = Task.objects.values('priority').annotate(count=Count('priority'))
        return JsonResponse(list(priority_counts), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['GET'])
def assigned_type_chart(request):
    try:
        assigned_counts = Task.objects.values('assigned_type').annotate(count=Count('assigned_type'))
        return JsonResponse(list(assigned_counts), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['GET'])
def task_completion_chart(request):
    try:
        completion_trend = (
            Task.objects.filter(status='completed')
            .annotate(month=TruncMonth('updated_at'))
            .values('month')
            .annotate(count=Count('id'))
            .order_by('month')
        )
        return JsonResponse(list(completion_trend), safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)