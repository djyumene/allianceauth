from django.contrib.auth import login
from django.contrib.auth import logout
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect
from django.utils import translation

from forms import LoginForm

import logging

logger = logging.getLogger(__name__)

def login_user(request):
    logger.debug("login_user called by user %s" % request.user)
    if request.method == 'POST':
        form = LoginForm(request.POST)
        logger.debug("Request of type POST, received form, valid: %s" % form.is_valid())
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            logger.debug("Authentication attempt with supplied credentials. Received user %s" % user)
            if user is not None:
                if user.is_active:
                    logger.info("Successful login attempt from user %s" % user)
                    login(request, user)
                    return redirect("/dashboard/")
                else:
                    logger.info("Login attempt failed for user %s: user marked inactive." % user)
            else:
                logger.info("Failed login attempt: provided username %s" % form.cleaned_data['username'])

            return render(request, 'public/login.html', context={'form': form, 'error': True})
    else:
        logger.debug("Providing new login form.")
        form = LoginForm()

    return render(request, 'public/login.html', context={'form': form})


def logout_user(request):
    logger.debug("logout_user called by user %s" % request.user)
    logoutUser = request.user
    logout(request)
    logger.info("Successful logout for user %s" % logoutUser)
    return redirect("/")
