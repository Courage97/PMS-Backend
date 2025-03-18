from django.urls import path,include
from .views import UserRegistrationView, UserLoginView, TeamMembersView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework.routers import DefaultRouter
from .views import TeamViewSet, TeamMembershipView, assign_role,TaskViewSet, CurrentUserView
from . import views
from .views import notifications_stream
from .views import task_status_chart, task_priority_chart, assigned_type_chart, task_completion_chart
router = DefaultRouter()
router.register('teams', TeamViewSet, basename='team')
router.register(r'task', TaskViewSet, basename='task')

urlpatterns = [
    path('api/register/', UserRegistrationView.as_view(), name='user-register'),
    path('api/login/', UserLoginView.as_view(), name='user-login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/users/', views.UserListView.as_view(), name='user-list'),
    path('api/users/me/', CurrentUserView.as_view(), name='current-user'),
    path('api/teams/<int:team_id>/members/', TeamMembersView.as_view(), name='team-members'),
    path('api/membership/',TeamMembershipView.as_view(), name='team-membership'),
    path('api/assign-role/', assign_role, name='assign-role'),
    path("notifications/stream/", notifications_stream, name="notifications-stream"),
    path('api/task_status/', task_status_chart, name='task_status_chart'),
    path('api/task_priority/', task_priority_chart, name='task_priority_chart'),
    path('api/assigned_type/', assigned_type_chart, name='assigned_type_chart'),
    path('api/task_completion/', task_completion_chart, name='task_completion_chart'),
    path('api/', include(router.urls)),
]