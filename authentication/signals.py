from django.db.models.signals import pre_save
from django.dispatch import receiver
from authentication.models import AuthServicesInfo
from authentication.states import MEMBER_STATE, BLUE_STATE
from celerytask.tasks import make_member, make_blue, disable_member
import logging

logger = logging.getLogger(__name__)

@receiver(pre_save, sender=AuthServicesInfo)
def pre_save_auth_state(sender, instance, *args, **kwargs):
    if instance.pk:
        old_instance = AuthServicesInfo.objects.get(pk=instance.pk)
        if old_instance.state != instance.state:
            logger.debug('Detected state change for %s' % instance.user)
            if instance.state == MEMBER_STATE:
                make_member(instance.user)
            elif instance.state == BLUE_STATE:
                make_blue(instance.user)
            else:
                disable_member(instance.user)
