from django.db import models
from django.contrib.auth.models import User
from authentication.states import MEMBER_STATE, BLUE_STATE, NONE_STATE

def get_none_state():
    return MembershipState.objects.get_or_create(name=NONE_STATE)[0]

class AuthServicesInfo(models.Model):
    STATE_CHOICES = (
        (NONE_STATE, 'None'),
        (BLUE_STATE, 'Blue'),
        (MEMBER_STATE, 'Member'),
    )

    ipboard_username = models.CharField(max_length=254, blank=True, default="")
    xenforo_username = models.CharField(max_length=254, blank=True, default="")
    forum_username = models.CharField(max_length=254, blank=True, default="")
    jabber_username = models.CharField(max_length=254, blank=True, default="")
    mumble_username = models.CharField(max_length=254, blank=True, default="")
    teamspeak3_uid = models.CharField(max_length=254, blank=True, default="")
    teamspeak3_perm_key = models.CharField(max_length=254, blank=True, default="")
    discord_uid = models.CharField(max_length=254, blank=True, default="")
    discourse_username = models.CharField(max_length=254, blank=True, default="")
    ips4_username = models.CharField(max_length=254, blank=True, default="")
    ips4_id = models.CharField(max_length=254, blank=True, default="")
    smf_username = models.CharField(max_length=254, blank=True, default="")
    market_username = models.CharField(max_length=254, blank=True, default="")
    main_char_id = models.CharField(max_length=64, blank=True, default="")
    is_blue = models.BooleanField(default=False)
    user = models.ForeignKey(User)
    state = models.CharField(blank=True, null=True, choices=STATE_CHOICES, default=NONE_STATE, max_length=10)

    def __str__(self):
        return self.user.username + ' - AuthInfo'
