from django.conf import settings
from celery.task import periodic_task
from django.contrib.auth.models import User
from django.contrib.auth.models import Group
from notifications import notify
from celery import task
from celery import group
from celery.task.schedules import crontab
from services.managers.openfire_manager import OpenfireManager
from services.managers.mumble_manager import MumbleManager
from services.managers.phpbb3_manager import Phpbb3Manager
from services.managers.ipboard_manager import IPBoardManager
from services.managers.xenforo_manager import XenForoManager
from services.managers.teamspeak3_manager import Teamspeak3Manager
from services.managers.discord_manager import DiscordOAuthManager
from services.managers.discourse_manager import DiscourseManager
from services.managers.smf_manager import smfManager
from services.models import AuthTS
from services.models import TSgroup
from authentication.models import AuthServicesInfo
from eveonline.managers import EveManager
from eveonline.models import EveApiKeyPair
from services.managers.eve_api_manager import EveApiManager
from util.common_task import validate_services
from util import add_member_permission
from util import remove_member_permission
from util import check_if_user_has_permission
from util.common_task import add_user_to_group
from util.common_task import remove_user_from_group
from util.common_task import generate_corp_group_name
from util.common_task import generate_alliance_group_name
from eveonline.models import EveCharacter
from eveonline.models import EveCorporationInfo
from eveonline.models import EveAllianceInfo
from authentication.managers import AuthServicesInfoManager
from services.models import DiscordAuthToken
from authentication.states import MEMBER_STATE, BLUE_STATE, NONE_STATE

import evelink
import time
import logging

logger = logging.getLogger(__name__)

def disable_member(user):
    change = False
    logger.debug("Disabling member %s" % user)
    if user.user_permissions.all().exists():
        logger.info("Clearning user %s permission to deactivate user." % user)
        user.user_permissions.clear()
        change = True
    if user.groups.all().exists():
        logger.info("Clearing user %s groups to deactivate user." % user)
        user.groups.clear()
        change = True
    validate_services(user)
    return change

def is_teamspeak3_active():
    return settings.ENABLE_AUTH_TEAMSPEAK3 or settings.ENABLE_BLUE_TEAMSPEAK3

@task
def update_jabber_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating jabber groups for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        groups.append('empty')
    logger.debug("Updating user %s jabber groups to %s" % (user, groups))
    try:
        OpenfireManager.update_user_groups(authserviceinfo.jabber_username, authserviceinfo.jabber_password, groups)
    except:
        logger.exception("Jabber group sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s jabber groups." % user)

@task
def update_all_jabber_groups():
    logger.debug("Updating ALL jabber groups")
    for user in AuthServicesInfo.objects.exclude(jabber_username__exact=''):
        update_jabber_groups.delay(user.user_id)

@task
def update_mumble_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating mumble groups for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        groups.append('empty')
    logger.debug("Updating user %s mumble groups to %s" % (user, groups))
    try:
        MumbleManager.update_groups(authserviceinfo.mumble_username, groups)
    except:
        logger.exception("Mumble group sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s mumble groups." % user)

@task
def update_all_mumble_groups():
    logger.debug("Updating ALL mumble groups")
    for user in AuthServicesInfo.objects.exclude(mumble_username__exact=''):
        update_mumble_groups.delay(user.user_id)

@task
def update_forum_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating forum groups for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        groups.append('empty')
    logger.debug("Updating user %s forum groups to %s" % (user, groups))
    try:
        Phpbb3Manager.update_groups(authserviceinfo.forum_username, groups)
    except:
        logger.exception("Phpbb group sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s forum groups." % user)

@task
def update_all_forum_groups():
    logger.debug("Updating ALL forum groups")
    for user in AuthServicesInfo.objects.exclude(forum_username__exact=''):
        update_forum_groups.delay(user.user_id)

@task
def update_smf_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating smf groups for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        groups.append('empty')
    logger.debug("Updating user %s smf groups to %s" % (user, groups))
    try:
        smfManager.update_groups(authserviceinfo.smf_username, groups)
    except:
        logger.exception("smf group sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s smf groups." % user)

@task
def update_all_smf_groups():
    logger.debug("Updating ALL smf groups")
    for user in AuthServicesInfo.objects.exclude(smf_username__exact=''):
        update_smf_groups.delay(user.user_id)

@task
def update_ipboard_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating user %s ipboard groups." % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        groups.append('empty')
    logger.debug("Updating user %s ipboard groups to %s" % (user, groups))
    try:
        IPBoardManager.update_groups(authserviceinfo.ipboard_username, groups)
    except:
        logger.exception("IPBoard group sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s ipboard groups." % user)

@task
def update_all_ipboard_groups():
    logger.debug("Updating ALL ipboard groups")
    for user in AuthServicesInfo.objects.exclude(ipboard_username__exact=''):
        update_ipboard_groups.delay(user.user_id)

@task
def update_teamspeak3_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating user %s teamspeak3 groups" % user)
    usergroups = user.groups.all()
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = {}
    for usergroup in usergroups:
        filtered_groups = AuthTS.objects.filter(auth_group=usergroup)
        if filtered_groups:
            for filtered_group in filtered_groups:
                for ts_group in filtered_group.ts_group.all():
                    groups[ts_group.ts_group_name] = ts_group.ts_group_id
    logger.debug("Updating user %s teamspeak3 groups to %s" % (user, groups))
    Teamspeak3Manager.update_groups(authserviceinfo.teamspeak3_uid, groups)
    logger.debug("Updated user %s teamspeak3 groups." % user)

@task
def update_all_teamspeak3_groups():
    logger.debug("Updating ALL teamspeak3 groups")
    for user in AuthServicesInfo.objects.exclude(teamspeak3_uid__exact=''):
        update_teamspeak3_groups.delay(user.user_id)

@task
def update_discord_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating discord groups for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        logger.debug("No syncgroups found for user. Adding empty group.")
        groups.append('empty')
    logger.debug("Updating user %s discord groups to %s" % (user, groups))
    try:
        DiscordOAuthManager.update_groups(authserviceinfo.discord_uid, groups)
    except:
        logger.exception("Discord group sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s discord groups." % user)

@task
def update_all_discord_groups():
    logger.debug("Updating ALL discord groups")
    for user in AuthServicesInfo.objects.exclude(discord_uid__exact=''):
        update_discord_groups.delay(user.user_id)

@task
def update_discord_nickname(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating discord nickname for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    character = EveManager.get_character_by_id(authserviceinfo.main_char_id)
    logger.debug("Updating user %s discord nickname to %s" % (user, character.character_name))
    try:
        DiscordOAuthManager.update_nickname(authserviceinfo.discord_uid, character.character_name)
    except:
        logger.exception("Discord nickname sync failed for %s, retrying in 10 mins" % user)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s discord nickname." % user)

@task
def update_all_discord_nicknames():
    logger.debug("Updating ALL discord nicknames")
    for user in AuthServicesInfo.objects.exclude(discord_uid__exact=''):
        update_discord_nickname(user.user_id)

@task
def update_discourse_groups(pk):
    user = User.objects.get(pk=pk)
    logger.debug("Updating discourse groups for user %s" % user)
    authserviceinfo = AuthServicesInfo.objects.get(user=user)
    groups = []
    for group in user.groups.all():
        groups.append(str(group.name))
    if len(groups) == 0:
        logger.debug("No syncgroups found for user. Adding empty group.")
        groups.append('empty')
    logger.debug("Updating user %s discourse groups to %s" % (user, groups))
    try:
        DiscourseManager.update_groups(authserviceinfo.discourse_username, groups)
    except:
        logger.warn("Discourse group sync failed for %s, retrying in 10 mins" % user, exc_info=True)
        raise self.retry(countdown = 60 * 10)
    logger.debug("Updated user %s discourse groups." % user)

@task
def update_all_discourse_groups():
    logger.debug("Updating ALL discourse groups")
    for user in AuthServicesInfo.objects.exclude(discourse_username__exact=''):
        update_discourse_groups.delay(user.user_id)


def assign_corp_group(auth):
    corp_group = None
    if auth.main_char_id:
        if EveCharacter.objects.filter(character_id=auth.main_char_id).exists():
            char = EveCharacter.objects.get(character_id=auth.main_char_id)
            corpname = generate_corp_group_name(char.corporation_name)
            state = determine_membership_by_character(char)
            if state == BLUE_STATE and settings.BLUE_CORP_GROUPS:
                logger.debug("Validating blue user %s has corp group assigned." % auth.user)
                corp_group, c = Group.objects.get_or_create(name=corpname)
            elif state == MEMBER_STATE and settings.MEMBER_CORP_GROUPS:
                logger.debug("Validating member %s has corp group assigned." % auth.user)
                corp_group, c = Group.objects.get_or_create(name=corpname)
            else:
                logger.debug("Ensuring %s has no corp groups assigned." % auth.user)
    if corp_group:
        if not corp_group in auth.user.groups.all():
            logger.info("Adding user %s to corp group %s" % (auth.user, corp_group))
            auth.user.groups.add(corp_group)
    for g in auth.user.groups.all():
        if str.startswith(str(g.name), "Corp_"):
            if g != corp_group:
                logger.info("Removing user %s from old corpgroup %s" % (auth.user, g))
                auth.user.groups.remove(g)

def assign_alliance_group(auth):
    alliance_group = None
    if auth.main_char_id:
        if EveCharacter.objects.filter(character_id=auth.main_char_id).exists():
            char = EveCharacter.objects.get(character_id=auth.main_char_id)
            if char.alliance_name:
                alliancename = generate_alliance_group_name(char.alliance_name)
                state = determine_membership_by_character(char)
                if state == BLUE_STATE and settings.BLUE_ALLIANCE_GROUPS:
                    logger.debug("Validating blue user %s has alliance group assigned." % auth.user)
                    alliance_group, c = Group.objects.get_or_create(name=alliancename)
                elif state == MEMBER_STATE and settings.MEMBER_ALLIANCE_GROUPS:
                    logger.debug("Validating member %s has alliance group assigned." % auth.user)
                    alliance_group, c = Group.objects.get_or_create(name=alliancename)
                else:
                    logger.debug("Ensuring %s has no alliance groups assigned." % auth.user)
            else:
                logger.debug("User %s main character %s not in an alliance. Ensuring no allinace group assigned." % (auth.user, char))
    if alliance_group:
        if not alliance_group in auth.user.groups.all():
            logger.info("Adding user %s to alliance group %s" % (auth.user, alliance_group))
            auth.user.groups.add(alliance_group)
    for g in auth.user.groups.all():
        if str.startswith(str(g.name), "Alliance_"):
            if g != alliance_group:
                logger.info("Removing user %s from old alliancegroup %s" % (auth.user, g))
                auth.user.groups.remove(g)

def make_member(user):
    logger.debug("Ensuring user %s has member permissions and groups." % user)
    # ensure member is not blue right now
    blue_group, c = Group.objects.get_or_create(name=settings.DEFAULT_BLUE_GROUP)
    if blue_group in user.groups.all():
        logger.info("Removing user %s blue group" % user)
        user.groups.remove(blue_group)
    # make member
    member_group, c = Group.objects.get_or_create(name=settings.DEFAULT_AUTH_GROUP)
    if not member_group in user.groups.all():
        logger.info("Adding user %s to member group" % user)
        user.groups.add(member_group)
    auth, c = AuthServicesInfo.objects.get_or_create(user=user)
    assign_corp_group(auth)
    assign_alliance_group(auth)

def make_blue(user):
    logger.debug("Ensuring user %s has blue permissions and groups." % user)
    # ensure user is not a member
    member_group, c = Group.objects.get_or_create(name=settings.DEFAULT_AUTH_GROUP)
    if member_group in user.groups.all():
        logger.info("Removing user %s member group" % user)
        user.groups.remove(member_group)
    # make blue
    blue_group, c = Group.objects.get_or_create(name=settings.DEFAULT_BLUE_GROUP)
    if not blue_group in user.groups.all():
        logger.info("Adding user %s to blue group" % user)
        user.groups.add(blue_group)
    auth, c = AuthServicesInfo.objects.get_or_create(user=user)
    assign_corp_group(auth)
    assign_alliance_group(auth)

def determine_membership_by_character(char):
    if settings.IS_CORP:
        if int(char.corporation_id) == int(settings.CORP_ID):
            logger.debug("Character %s in owning corp id %s" % (char, char.corporation_id))
            return MEMBER_STATE
    else:
        if int(char.alliance_id) == int(settings.ALLIANCE_ID):
            logger.debug("Character %s in owning alliance id %s" % (char, char.alliance_id))
            return MEMBER_STATE
    if EveCorporationInfo.objects.filter(corporation_id=char.corporation_id).exists() is False:
         logger.debug("No corp model for character %s corp id %s. Unable to check standings. Non-member." % (char, char.corporation_id))
         return NONE_STATE
    else:
         corp = EveCorporationInfo.objects.get(corporation_id=char.corporation_id)
         if corp.is_blue:
             logger.debug("Character %s member of blue corp %s" % (char, corp))
             return BLUE_STATE
         else:
             logger.debug("Character %s member of non-blue corp %s. Non-member." % (char, corp))
             return NONE_STATE

def determine_membership_by_user(user):
    logger.debug("Determining membership of user %s" % user)
    auth, c = AuthServicesInfo.objects.get_or_create(user=user)
    if auth.main_char_id:
        if EveCharacter.objects.filter(character_id=auth.main_char_id).exists():
            char = EveCharacter.objects.get(character_id=auth.main_char_id)
            return determine_membership_by_character(char)
        else:
            logger.debug("Character model matching user %s main character id %s does not exist. Non-member." % (user, auth.main_char_id))
            return NONE_STATE
    else:
        logger.debug("User %s has no main character set. Non-member." % user)
        return NONE_STATE

def set_state(user):
    if user.is_active:
        state = determine_membership_by_user(user)
    else:
        state = NONE_STATE
    logger.debug("Assigning user %s to state %s" % (user, state))
    auth = AuthServicesInfo.objects.get_or_create(user=user)[0]
    if auth.state != state:
       auth.state = state
       auth.save()
       notify(user, "Membership State Change", message="You membership state has been changed to %s" % state)

@task
def refresh_api(api):
    logger.debug('Running update on api key %s' % api.api_id)
    still_valid = True
    try:
        EveApiManager.validate_api(api.api_id, api.api_key, api.user)
        # Update characters
        characters = EveApiManager.get_characters_from_api(api.api_id, api.api_key)
        EveManager.update_characters_from_list(characters)
        new_character = False
        for char in characters.result:
            # Ensure we have a model for all characters on key
            if not EveManager.check_if_character_exist(characters.result[char]['name']):
                logger.debug("API key %s has a new character on the account: %s" % (api.api_id, characters.result[char]['name']))
                new_character = True
        if new_character:
            logger.debug("Creating new character %s from api key %s" % (characters.result[char]['name'], api.api_id))
            EveManager.create_characters_from_list(characters, api.user, api.api_id)
        current_chars = EveCharacter.objects.filter(api_id=api.api_id)
        for c in current_chars:
            if not int(c.character_id) in characters.result:
                logger.info("Character %s no longer found on API ID %s" % (c, api.api_id))
                c.delete()
    except evelink.api.APIError as e:
        logger.warning('Received unexpected APIError (%s) while updating API %s' % (e.code, api.api_id))
    except EveApiManager.ApiInvalidError as e:
        logger.debug("API key %s is no longer valid; it and its characters will be deleted." % api.api_id)
        notify(api.user, "API Failed Validation", message="Your API key ID %s is no longer valid." % api.api_id, level="danger")
        still_valid = False
    except EveApiManager.ApiAccountValidationError as e:
        logger.info("Determined api key %s for user %s no longer meets account access requirements." % (api.api_id, api.user))
        notify(api.user, "API Failed Validation", message="Your API key ID %s is no longer account-wide as required." % api.api_id, level="danger")
        still_valid = False
    except EveApiManager.ApiMaskValidationError as e:
        logger.info("Determined api key %s for user %s no longer meets minimum access mask as required." % (api.api_id, api.user))
        notify(api.user, "API Failed Validation", message="Your API key ID %s no longer meets access mask requirements. Required: %s Got: %s" % (api.api_id, e.required_mask, e.api_mask), level="danger")
        still_valid = False
    finally:
        if not still_valid:
            EveManager.delete_characters_by_api_id(api.api_id, api.user.id)
            EveManager.delete_api_key_pair(api.api_id, api.user.id)
            notify(api.user, "API Key Deleted", message="Your API key ID %s is invalid. It and its associated characters have been deleted." % api.api_id, level="danger")

@task
def refresh_user_apis(user):
    logger.debug('Refreshing all APIs belonging to user %s' % user)
    apis = EveApiKeyPair.objects.filter(user=user)
    job = group([refresh_api.s(x) for x in apis])()
    # await completion of all refreshes
    job.get()
    # Check our main character
    auth = AuthServicesInfo.objects.get_or_create(user=user)[0]
    if auth.main_char_id:
        if EveCharacter.objects.filter(character_id=auth.main_char_id).exists() is False:
            logger.info("User %s main character id %s missing model. Clearning main character." % (user, auth.main_char_id))
            authserviceinfo.main_char_id = ''
            authserviceinfo.save()
            notify(user, "Main Character Reset", message="Your specified main character no longer has a model.\nThis could be the result of an invalid API\nYour main character ID has been reset.", level="warn")
    set_state(user)

@periodic_task(run_every=crontab(minute=0, hour="*/3"))
def run_api_refresh():
    for u in User.objects.all():
        refresh_user_apis.delay(u)

def populate_alliance(id, blue=False):
    logger.debug("Populating alliance model with id %s blue %s" % (id, blue))
    alliance_info = EveApiManager.get_alliance_information(id)

    if not alliance_info:
        raise ValueError("Supplied alliance id %s is invalid" % id)

    if EveAllianceInfo.objects.filter(alliance_id=id).exists():
        alliance = EveAllianceInfo.objects.get(alliance_id=id)
    else:
        EveManager.create_alliance_info(alliance_info['id'], alliance_info['name'], alliance_info['ticker'],
                                             alliance_info['executor_id'], alliance_info['member_count'], blue)
    alliance = EveAllianceInfo.objects.get(alliance_id=id)
    for member_corp in alliance_info['member_corps']:
        if EveCorporationInfo.objects.filter(corporation_id=member_corp).exists():
            corp = EveCorporationInfo.objects.get(corporation_id=member_corp)
            if corp.alliance != alliance:
                corp.alliance = alliance
                corp.save()
        else:
            logger.info("Creating new alliance member corp id %s" % member_corp)
            corpinfo = EveApiManager.get_corporation_information(member_corp)
            EveManager.create_corporation_info(corpinfo['id'], corpinfo['name'], corpinfo['ticker'],
                                                    corpinfo['members']['current'], blue, alliance)

@task
def update_alliance(id):
    alliance = EveAllianceInfo.objects.get(alliance_id=id)
    corps = EveCorporationInfo.objects.filter(alliance=alliance)
    logger.debug("Updating alliance %s with %s member corps" % (alliance, len(corps)))
    allianceinfo = EveApiManager.get_alliance_information(alliance.alliance_id)
    if allianceinfo:
        EveManager.update_alliance_info(allianceinfo['id'], allianceinfo['executor_id'],
                                        allianceinfo['member_count'], alliance.is_blue)
        for corp in corps:
            if corp.corporation_id in allianceinfo['member_corps'] is False:
                logger.info("Corp %s no longer in alliance %s" % (corp, alliance))
                corp.alliance = None
                corp.save()
        populate_alliance(alliance.alliance_id, blue=alliance.is_blue)
    elif EveApiManager.check_if_alliance_exists(alliance.alliance_id) is False:
        logger.info("Alliance %s has closed. Deleting model" % alliance)
        alliance.delete()

@task
def update_corp(id):
    corp = EveCorporationInfo.objects.get(corporation_id=id)
    logger.debug("Updating corp %s" % corp)
    corpinfo = EveApiManager.get_corporation_information(corp.corporation_id)
    if corpinfo:
        alliance = None
        if EveAllianceInfo.objects.filter(alliance_id=corpinfo['alliance']['id']).exists():
            alliance = EveAllianceInfo.objects.get(alliance_id=corpinfo['alliance']['id'])
        EveManager.update_corporation_info(corpinfo['id'], corpinfo['members']['current'], alliance, corp.is_blue)
    elif EveApiManager.check_if_corp_exists(corp.corporation_id) is False:
        logger.info("Corp %s has closed. Deleting model" % corp)
        corp.delete()    

# Run Every 2 hours
@periodic_task(run_every=crontab(minute=0, hour="*/2"))
def run_corp_update():
    if EveApiManager.check_if_api_server_online() is False:
        logger.warn("Aborted updating corp and alliance models: API server unreachable")
        return
    standing_level = 'alliance'
    try:
        # get corp info for owning corp if required
        ownercorpinfo = {}
        if settings.IS_CORP:
            standing_level = 'corp'
            logger.debug("Getting information for owning corp with id %s" % settings.CORP_ID)
            ownercorpinfo = EveApiManager.get_corporation_information(settings.CORP_ID)
            if not ownercorpinfo:
                logger.error("Failed to retrieve corp info for owning corp id %s - bad corp id?" % settings.CORP_ID)
                return
    
        # check if we need to update an alliance model
        alliance_id = ''
        if ownercorpinfo and ownercorpinfo['alliance']['id']:
            alliance_id = ownercorpinfo['alliance']['id']
        elif settings.IS_CORP is False:
            alliance_id = settings.ALLIANCE_ID
    
        # get and create alliance info for owning alliance if required
        alliance = None
        if alliance_id:
            logger.debug("Getting information for owning alliance with id %s" % alliance_id)
            ownerallianceinfo = EveApiManager.get_alliance_information(alliance_id)
            if not ownerallianceinfo:
                logger.error("Failed to retrieve corp info for owning alliance id %s - bad alliance id?" % alliance_id)
                return
            if EveAllianceInfo.objects.filter(alliance_id=ownerallianceinfo['id']).exists():
                logger.debug("Updating existing owner alliance model with id %s" % alliance_id)
                EveManager.update_alliance_info(ownerallianceinfo['id'], ownerallianceinfo['executor_id'], ownerallianceinfo['member_count'], False)
            else:
                populate_alliance(alliance_id)
                alliance = EveAllianceInfo.objects.get(alliance_id=alliance_id)
    
        # create corp info for owning corp if required
        if ownercorpinfo:
            if EveCorporationInfo.objects.filter(corporation_id=ownercorpinfo['id']).exists():
                logger.debug("Updating existing owner corp model with id %s" % ownercorpinfo['id'])
                EveManager.update_corporation_info(ownercorpinfo['id'], ownercorpinfo['members']['current'], alliance, False)
            else:
                logger.info("Creating model for owning corp with id %s" % ownercorpinfo['id'])
                EveManager.create_corporation_info(ownercorpinfo['id'], ownercorpinfo['name'], ownercorpinfo['ticker'],
                                                       ownercorpinfo['members']['current'], False, alliance)

        # validate and create corp models for member corps of owning alliance
        if alliance:
            current_corps = EveCorporationInfo.objects.filter(alliance=alliance)
            for corp in current_corps:
                if corp.corporation_id in ownerallianceinfo['member_corps'] is False:
                    logger.info("Corp %s is no longer in owning alliance %s - updating model." % (corp, alliance))
                    corp.alliance = None
                    corp.save()
            for member_corp in ownerallianceinfo['member_corps']:
                if EveCorporationInfo.objects.filter(corporation_id=member_corp).exists():
                    corp = EveCorporationInfo.objects.get(corporation_id=member_corp)
                    if corp.alliance == alliance is not True:
                        logger.info("Associating corp %s with owning alliance %s" % (corp, alliance))
                        corp.alliance = alliance
                        corp.save()
                else:
                    corpinfo = EveApiManager.get_corporation_information(member_corp)
                    logger.info("Creating model for owning alliance member corp with id %s" % corpinfo['id'])
                    EveManager.create_corporation_info(corpinfo['id'], corpinfo['name'], corpinfo['ticker'],
                                                       corpinfo['members']['current'], False, alliance)

        # update existing corp models
        for corp in EveCorporationInfo.objects.all():
            update_corp.delay(corp.corporation_id)

        # update existing alliance models
        for alliance in EveAllianceInfo.objects.all():
            update_alliance.delay(alliance.alliance_id)

        # create standings
        standings = EveApiManager.get_corp_standings()
        if standings:
            standings = standings[standing_level]
            for standing in standings:
                if int(standings[standing]['standing']) >= settings.BLUE_STANDING:
                    logger.debug("Standing %s meets threshold" % standing)
                    if EveApiManager.check_if_id_is_alliance(standing):
                        logger.debug("Standing %s is an alliance" % standing)
                        if EveAllianceInfo.objects.filter(alliance_id=standing).exists():
                            alliance = EveAllianceInfo.objects.get(alliance_id=standing)
                            if alliance.is_blue is not True:
                                logger.info("Updating alliance %s as blue" % alliance)
                                alliance.is_blue = True
                                alliance.save()
                        else:
                            populate_alliance(standing, blue=True)
                    elif EveApiManager.check_if_id_is_corp(standing):
                        logger.debug("Standing %s is a corp" % standing)
                        if EveCorporationInfo.objects.filter(corporation_id=standing).exists():
                            corp = EveCorporationInfo.objects.get(corporation_id=standing)
                            if corp.is_blue is not True:
                                logger.info("Updating corp %s as blue" % corp)
                                corp.is_blue = True
                                corp.save()
                        else:
                            logger.info("Creating model for blue corp with id %s" % standing)
                            corpinfo = EveApiManager.get_corporation_information(standing)
                            corp_alliance = None
                            if EveAllianceInfo.objects.filter(alliance_id=corpinfo['alliance']['id']).exists():
                                logger.debug("New corp model for standing %s has existing alliance model" % standing)
                                corp_alliance = EveAllianceInfo.objects.get(alliance_id=corpinfo['alliance']['id'])
                            EveManager.create_corporation_info(corpinfo['id'], corpinfo['name'], corpinfo['ticker'],
                                                               corpinfo['members']['current'], True, corp_alliance)
                    

        # update alliance standings
        for alliance in EveAllianceInfo.objects.filter(is_blue=True):
            if int(alliance.alliance_id) in standings:
                if float(standings[int(alliance.alliance_id)]['standing']) < float(settings.BLUE_STANDING):
                    logger.info("Alliance %s no longer meets minimum blue standing threshold" % alliance)
                    alliance.is_blue = False
                    alliance.save()
            else:
                logger.info("Alliance %s no longer in standings" % alliance)
                alliance.is_blue = False
                alliance.save()
    
        # update corp standings
        for corp in EveCorporationInfo.objects.filter(is_blue=True):
            if int(corp.corporation_id) in standings:
                if float(standings[int(corp.corporation_id)]['standing']) < float(settings.BLUE_STANDING):
                    logger.info("Corp %s no longer meets minimum blue standing threshold" % corp)
                    corp.is_blue = False
                    corp.save()
            else:
                if corp.alliance:
                    if not corp.alliance.is_blue:
                        logger.info("Corp %s and its alliance %s are no longer blue" % (corp, corp.alliance))
                        corp.is_blue = False
                        corp.save()
                else:
                    logger.info("Corp %s is no longer blue" % corp)
                    corp.is_blue = False
                    corp.save()

        # delete unnecessary alliance models
        for alliance in EveAllianceInfo.objects.filter(is_blue=False):
            logger.debug("Checking to delete alliance %s" % alliance)
            if not settings.IS_CORP:
                if not alliance.alliance_id == settings.ALLIANCE_ID:
                    logger.info("Deleting unnecessary alliance model %s" % alliance)
                    alliance.delete()
            else:
                if not alliance.evecorporationinfo_set.filter(corporation_id=settings.CORP_ID).exists():
                    logger.info("Deleting unnecessary alliance model %s" % alliance)
                    alliance.delete()

        # delete unnecessary corp models
        for corp in EveCorporationInfo.objects.filter(is_blue=False):
            logger.debug("Checking to delete corp %s" % corp)
            if not settings.IS_CORP:
                if corp.alliance:
                    logger.debug("Corp %s has alliance %s" % (corp, corp.alliance))
                    if not corp.alliance.alliance_id == settings.ALLIANCE_ID:
                        logger.info("Deleting unnecessary corp model %s" % corp)
                        corp.delete()
                else:
                    logger.info("Deleting unnecessary corp model %s" % corp)
                    corp.delete()
            else:
                if corp.corporation_id != settings.CORP_ID:
                    logger.debug("Corp %s is not owning corp" % corp)
                    if corp.alliance:
                        logger.debug("Corp %s has alliance %s" % (corp, corp.alliance))
                        if not corp.alliance.evecorporationinfo_set.filter(corporation_id=settings.CORP_ID).exists():
                            logger.info("Deleting unnecessary corp model %s" % corp)
                            corp.delete()
                    else:
                        logger.info("Deleting unnecessary corp model %s" % corp)
                        corp.delete()
                else:
                    logger.debug("Corp %s is owning corp" % corp)
    except evelink.api.APIError as e:
        logger.error("Model update failed with error code %s" % e.code)

@periodic_task(run_every=crontab(minute="*/30"))
def run_ts3_group_update():
    if is_teamspeak3_active():
        logger.debug("TS3 installed. Syncing local group objects.")
        Teamspeak3Manager._sync_ts_group_db()
