from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
# Create your models here.

# Extend the AbstractUser model to add custom fields
class TeamUser(AbstractUser):
    # Define role choices for users
    ADMIN = 'Admin'
    MANAGER = 'Manager'
    TEAM_MEMBER = 'Team Member'
    VIEWER = 'Viewer'

    ROLE_CHOICES = [
    ('Admin', 'Admin'),
    ('Manager', 'Manager'),
    ('Team Member', 'Team Member'),
    ('Viewer', 'Viewer'),
]


    # Custom fields for the user model
    email = models.EmailField(unique=True)  # Use email as the unique identifier for login
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default= 'ADMIN')  # User role
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)  # Profile picture
    bio = models.TextField(blank=True)  # Optional bio field

    # Set email as the primary field for authentication
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']  # Fields required during user creation 


    def is_admin(self):
        return self.role == self.ADMIN

    def is_manager(self):
        return self.role == self.MANAGER

    def is_team_member(self):
        return self.role == self.TEAM_MEMBER
    
    def is_viewer(self):
        return self.role == self.VIEWER

    def __str__(self):
        return f"{self.username} - {self.get_role_display()}"
    
# Team management model
class Team(models.Model):
    name = models.CharField(max_length=255) 
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    
class TeamMembership(models.Model):
    user = models.ForeignKey(TeamUser, on_delete=models.CASCADE, related_name="team_memberships")
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name="members")
    class Meta:
        unique_together = ('user', 'team')  # Ensures a user cannot belong to the same team twice

    def __str__(self):
        return f"{self.user.username} - {self.team.name} ({self.role})"

    def is_admin(self):
        return self.role.lower() == 'admin'

    def is_manager(self):
        return self.role.lower() == 'manager'

    def is_member(self):
        return self.role.lower() == 'team member'

    
# Task management system
class Task(models.Model):
    
    PRIORITY_CHOICES = [
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('blocked', 'Blocked'),
    ]
    ASSIGNED_TYPE_CHOICES = [
    ('USER', 'User'),
    ('TEAM', 'Team'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='MEDIUM')
    deadline = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    assigned_to_team = models.ForeignKey(Team, related_name='assigned_tasks_team', null=True, on_delete=models.SET_NULL)
    assigned_to_user = models.ForeignKey(TeamUser, related_name='assigned_tasks_user', null=True, on_delete=models.SET_NULL)
    created_by = models.ForeignKey(TeamUser, related_name='created_tasks', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_type = models.CharField(max_length=20, choices=ASSIGNED_TYPE_CHOICES, default='USER')

    # this line of code is to create newest task and fast searching
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'priority']),
            models.Index(fields=['deadline']),
        ]
    def __str__(self):
        return f"{self.title} ({self.get_status_display()})"

    def is_overdue(self):
        if self.deadline and self.status != 'completed':
            return self.deadline < timezone.now()
        return False


    