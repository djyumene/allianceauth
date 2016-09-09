import uuid

from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.conf import settings

import logging

logger = logging.getLogger(__name__)

def add_member_permission(user, permission):
    logger.debug("Adding permission %s to member %s" % (permission, user))
    ct = ContentType.objects.get_for_model(User)
    stored_permission, created = Permission.objects.get_or_create(codename=permission,
                                                                  content_type=ct, name=permission)
    user = User.objects.get(username=user.username)
    user.user_permissions.add(stored_permission)
    logger.info("Added permission %s to user %s" % (permission, user))
    user.save()


def remove_member_permission(user, permission):
    logger.debug("Removing permission %s from member %s" % (permission, user))
    ct = ContentType.objects.get_for_model(User)
    stored_permission, created = Permission.objects.get_or_create(codename=permission,
                                                                  content_type=ct, name=permission)

    user = User.objects.get(username=user.username)

    if user.has_perm('auth.' + permission):
        user.user_permissions.remove(stored_permission)
        user.save()
        logger.info("Removed permission %s from member %s" % (permission, user))
    else:
        logger.warn("Attempting to remove permission user %s does not have: %s" % (user, permission))


def check_if_user_has_permission(user, permission):
    ct = ContentType.objects.get_for_model(User)
    stored_permission, created = Permission.objects.get_or_create(codename=permission,
                                                                  content_type=ct, name=permission)
    return user.has_perm('auth.' + permission)


def random_string(string_length=10):
    """Returns a random string of length string_length."""
    random = str(uuid.uuid4())  # Convert UUID format to a Python string.
    random = random.upper()  # Make all characters uppercase.
    random = random.replace("-", "")  # Remove the UUID '-'.
    return random[0:string_length]  # Return the random string.
