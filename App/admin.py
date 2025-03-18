from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import TeamUser, Team, TeamMembership, Task

# Customize TeamUser admin
class TeamUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'role', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email')
    ordering = ('username',)

# Customize Team admin
class TeamAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at', 'updated_at')
    search_fields = ('name',)
    list_filter = ('created_at',)

# Customize TeamMembership admin
class TeamMembershipAdmin(admin.ModelAdmin):
    list_display = ('user', 'team')
    list_filter = ('team',)
    search_fields = ('user__username', 'team__name')

# Customize Task admin
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'status', 'priority', 'deadline', 'assigned_type')
    list_filter = ('status', 'priority', 'assigned_type')
    search_fields = ('title', 'description')
    date_hierarchy = 'created_at'

# Register all models with their custom admin classes
admin.site.register(TeamUser, TeamUserAdmin)
admin.site.register(Team, TeamAdmin)
admin.site.register(TeamMembership, TeamMembershipAdmin)
admin.site.register(Task, TaskAdmin)