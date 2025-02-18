from rest_framework import permissions
from .models import TeamMembership

class BaseTeamPermission(permissions.BasePermission):
    def get_team_id(self, request, view):
        return view.kwargs.get('team_id') or request.data.get('team_id')

    def get_membership(self, request, team_id):
        return TeamMembership.objects.filter(
            user=request.user,
            team_id=team_id
        ).first()

class IsTeamAdmin(BaseTeamPermission):
    def has_permission(self, request, view):
        team_id = self.get_team_id(request, view)
        membership = self.get_membership(request, team_id)
        return membership and membership.is_admin()

class IsTeamManager(BaseTeamPermission):
    def has_permission(self, request, view):
        team_id  = self.get_team_id(request, view)
        membership  = self.get_membership(request, team_id)
        return membership and membership.is_manager()


class IsTeamMember(BaseTeamPermission):
    def has_permission(self, request, view):
        team_id = self.get_team_id(request, view)
        return self.get_membership(request, team_id) is not None
