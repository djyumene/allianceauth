from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.utils import translation
from django.contrib import messages

from forms import RegistrationForm

import logging

logger = logging.getLogger(__name__)

def register_user_view(request):
    logger.debug("register_user_view called by user %s" % request.user)
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        logger.debug("Request type POST contains form valid: %s" % form.is_valid())
        if form.is_valid():

            if not User.objects.filter(username=form.cleaned_data['username']).exists():
                user = User.objects.create_user(form.cleaned_data['username'],
                                                form.cleaned_data['email'], form.cleaned_data['password'])

                user.save()
                logger.info("Created new user %s" % user)
                messages.warning(request, 'Add an API key to set up your account.')
                return redirect("auth_dashboard")

            else:
                logger.error("Unable to register new user: username %s already exists." % form.cleaned_data['username'])
                return render(request, 'public/register.html', context={'form': form, 'error': True})
        else:
            logger.debug("Registration form invalid. Returning for user %s to make corrections." % request.user)

    else:
        logger.debug("Returning blank registration form.")
        form = RegistrationForm()

    return render(request, 'public/register.html', context={'form': form})
