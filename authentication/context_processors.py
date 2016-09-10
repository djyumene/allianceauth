from authentication.models import AuthServicesInfo
from authentication.states import NONE_STATE, BLUE_STATE, MEMBER_STATE

def membership_state(request):
    if request.user.is_authenticated:
        auth = AuthServicesInfo.objects.get_or_create(user=request.user)[0]
        return {'STATE':auth.state}
    return {'STATE':NONE_STATE}

def states(request):
    return {
        'BLUE_STATE': BLUE_STATE,
        'MEMBER_STATE': MEMBER_STATE,
        'NONE_STATE': NONE_STATE,
        'MEMBER_BLUE_STATE': [MEMBER_STATE, BLUE_STATE],
    }