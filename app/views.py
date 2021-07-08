from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.template.loader import get_template, render_to_string
from web_project import settings
from datetime import datetime
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.models import User
from app.models import BingAdsUser
from bingads import *

# import logging
# logging.basicConfig(level=logging.INFO)
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
# logging.getLogger('suds.transport').setLevel(logging.DEBUG)

authorization_data = AuthorizationData(
    account_id=None,
    customer_id=None,
    developer_token=None,
    authentication=None)

customer_service=None

def home(request):
    """
    If an authenticated user returns to this page after logging in, the appropriate
    context is provided to index.html for rendering the page.
    """
    assert isinstance(request, HttpRequest)

    # If the Django user has a refresh token stored,
    # try to use it to get Microsoft Advertising data.
    if user_has_refresh_token(request.user.username):
        return redirect('/callback')
    else:
        return render(
            request,
            'app/index.html'
        )

def callback(request):
    """Handles OAuth authorization, either via callback or direct refresh request."""
    assert isinstance(request, HttpRequest)

    authentication = OAuthWebAuthCodeGrant(
        client_id=settings.CLIENT_ID,
        client_secret=settings.CLIENT_SECRET,
        redirection_uri=settings.REDIRECTION_URI,
        env=settings.ENVIRONMENT)

    return authorize_bing_ads_user(request, authentication)

def authorize_bing_ads_user(request, authentication):
    assert isinstance(request, HttpRequest)

    global customer_service
    bingadsuser = None

    try:
        Users = get_user_model()
        user = User.objects.get(username=request.user.username)
    except User.DoesNotExist:
        return render(
            request,
            'app/index.html'
        )

    try:
        bingadsuser = user.bingadsuser
    except BingAdsUser.DoesNotExist:
        bingadsuser = BingAdsUser()
        bingadsuser.user = user
        pass

    try:
        # If we have a refresh token let's refresh the access token.
        if(bingadsuser is not None and bingadsuser.refresh_token != ""):
            authentication.request_oauth_tokens_by_refresh_token(bingadsuser.refresh_token)
            bingadsuser.refresh_token = authentication.oauth_tokens.refresh_token

        # If the current HTTP request is a callback from the Microsoft Account authorization server,
        # use the current request url containing authorization code to request new access and refresh tokens.
        elif (request.GET.get('code') is not None):
            authentication.request_oauth_tokens_by_response_uri(response_uri = request.get_full_path())
            bingadsuser.refresh_token = authentication.oauth_tokens.refresh_token
    except OAuthTokenRequestException:
        bingadsuser.refresh_token = ""

    user.save()
    bingadsuser.save()

    # If there is no refresh token saved and no callback from the authorization server,
    # then connect to the authorization server and request user consent.
    if (bingadsuser.refresh_token == ""):
        return redirect(authentication.get_authorization_endpoint())

    set_session_data(request, authentication)

    # At this point even if the user has valid Django web application credentials,
    # we don't know whether they have access to Microsoft Advertising.
    # Let's test to see if they can call Bing Ads API service operations.

    bing_ads_user = None
    accounts=[]
    errors=[]

    try:
        bing_ads_user = get_user(None)
        accounts = search_accounts_by_user_id(bing_ads_user.Id)['AdvertiserAccount']
    except WebFault as ex:
        errors=get_webfault_errors(ex)
        pass

    context = {
        'bingadsuser': bing_ads_user,
        'accounts': accounts,
        'errors': errors,
    }
    return render(
        request,
        'app/index.html',
        context
    )

def revoke(request):
    """Deletes the refresh token for the user authenticated in the current session."""
    assert isinstance(request, HttpRequest)

    try:
        Users = get_user_model()
        user = User.objects.get(username=request.user.username)
        bingadsuser = user.bingadsuser
        if(bingadsuser is not None):
            bingadsuser.refresh_token = ""
            bingadsuser.save()
    except User.DoesNotExist:
        pass
    except BingAdsUser.DoesNotExist:
        pass

    clear_session_data(request)

    return render(
        request,
        'app/index.html'
    )

def user_has_active_session(request):
    try:
        return True if request.session['is_authenticated'] else False
    except KeyError:
        return False

def user_has_refresh_token(username):
    try:
        Users = get_user_model()
        user = User.objects.get(username=username)
        bingadsuser = user.bingadsuser
        if(bingadsuser is not None and bingadsuser.refresh_token != ""):
            return True
    except User.DoesNotExist:
        return False
    except BingAdsUser.DoesNotExist:
        return False

def set_session_data(request, authentication):
    global authorization_data
    global customer_service

    try:
        request.session['is_authenticated'] = True

        authorization_data.authentication = authentication
        authorization_data.developer_token = settings.DEVELOPER_TOKEN

        customer_service = ServiceClient(
            service='CustomerManagementService',
            version=settings.API_VERSION,
            authorization_data=authorization_data,
            environment=settings.ENVIRONMENT
        )

    except KeyError:
        pass
    return None

def clear_session_data(request):
    global authorization_data
    global customer_service

    request.session['is_authenticated'] = False

    authorization_data = AuthorizationData(account_id=None, customer_id=None, developer_token=None, authentication=None)
    customer_service = None

def applogout(request):
    logout(request)
    clear_session_data(request)
    return redirect('/')

def get_user(user_id):
    '''
    Gets a Microsoft Advertising User object by the specified user ID.

    :param user_id: The Microsoft Advertising user identifier.
    :type user_id: long
    :return: The Microsoft Advertising user.
    :rtype: User
    '''
    global customer_service

    return customer_service.GetUser(UserId = user_id).User

def search_accounts_by_user_id(user_id):
    '''
    Search for account details by UserId.

    :param user_id: The Microsoft Advertising user identifier.
    :type user_id: long
    :return: List of accounts that the user can manage.
    :rtype: Dictionary of AdvertiserAccount
    '''

    predicates={
        'Predicate': [
            {
                'Field': 'UserId',
                'Operator': 'Equals',
                'Value': user_id,
            },
        ]
    }

    accounts=[]

    page_index = 0
    PAGE_SIZE=100
    found_last_page = False

    while (not found_last_page):
        paging=set_elements_to_none(customer_service.factory.create('ns5:Paging'))
        paging.Index=page_index
        paging.Size=PAGE_SIZE
        search_accounts_response = customer_service.SearchAccounts(
            PageInfo=paging,
            Predicates=predicates
        )

        if search_accounts_response is not None and hasattr(search_accounts_response, 'AdvertiserAccount'):
            accounts.extend(search_accounts_response['AdvertiserAccount'])
            found_last_page = PAGE_SIZE > len(search_accounts_response['AdvertiserAccount'])
            page_index += 1
        else:
            found_last_page=True

    return {
        'AdvertiserAccount': accounts
    }

def set_elements_to_none(suds_object):
    for (element) in suds_object:
        suds_object.__setitem__(element[0], None)
    return suds_object

def get_webfault_errors(ex):
    errors=[]

    if not hasattr(ex.fault, "detail"):
        raise Exception("Unknown WebFault")

    error_attribute_sets = (
        ["ApiFault", "OperationErrors", "OperationError"],
        ["AdApiFaultDetail", "Errors", "AdApiError"],
        ["ApiFaultDetail", "BatchErrors", "BatchError"],
        ["ApiFaultDetail", "OperationErrors", "OperationError"],
        ["EditorialApiFaultDetail", "BatchErrors", "BatchError"],
        ["EditorialApiFaultDetail", "EditorialErrors", "EditorialError"],
        ["EditorialApiFaultDetail", "OperationErrors", "OperationError"],
    )

    for error_attribute_set in error_attribute_sets:
        errors = get_api_errors(ex.fault.detail, error_attribute_set)
        if errors is not None:
            return errors

    return None

def get_api_errors(error_detail, error_attribute_set):
    api_errors = error_detail
    for field in error_attribute_set:
        api_errors = getattr(api_errors, field, None)
    if api_errors is None:
        return None

    errors=[]
    if type(api_errors) == list:
        for api_error in api_errors:
            errors.append(api_error)
    else:
        errors.append(api_errors)
    return errors
