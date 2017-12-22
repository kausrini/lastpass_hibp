#!/usr/bin/env python
# coding: utf-8
from __future__ import print_function

import requests
import sys
import time
import getpass

from lastpass import (
    Vault,
    LastPassIncorrectYubikeyPasswordError,
    LastPassIncorrectGoogleAuthenticatorCodeError,
    LastPassUnknownError
)

BASE_URL = "https://haveibeenpwned.com/api/v2/"
HEADERS = {"User-Agent": "lastpass-hibp",}


class Site(object):

    def __init__(self, id, name, username, password, url, group, notes):
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.url = url
        self.group = group
        self.notes = notes

def fetch_lastpass_vault(username, password):
    DEVICE_ID = "My Python Script"

    vault = None
    try:
        # First try without a multifactor password
        vault = Vault.open_remote(username, password, None, DEVICE_ID)
    except LastPassIncorrectGoogleAuthenticatorCodeError as e:
        # Get the code
        multifactor_password = input('Enter Google Authenticator code:')

        # And now retry with the code
        vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)
    except LastPassIncorrectYubikeyPasswordError as e:
        # Get the code
        multifactor_password = input('Enter Yubikey password:')
        # And now retry with the code
        vault = Vault.open_remote(username, password, multifactor_password, DEVICE_ID)
    except LastPassUnknownError as e:
        if 'Multifactor authentication required!' in str(e):
            print('Use lastpass authenticator app to accept login')

    if vault is None:
        print('{Error] Unable to initialize vault')
        sys.exit(1)
    return vault


def get_lastpass_credentials():
    while True:
        sys.stdout.write('Enter the Username for lastpass : ')
        username = input()
        if len(username):
            break
        else:
            print('[ERROR] Please enter an Username for lastpass')

    while True:
        print('before')
        password = getpass.getpass('Enter Password : ')
        verify_password = getpass.getpass('Re-enter Password : ')
        print('after')
        if password == verify_password:
            break
        else:
            print("[Error] The passwords do not match. Please enter again.")

    return username, password

def parse_vault(vault):
    sites = []
    for _, i in enumerate(vault.accounts):
        sites.append(Site(i.id.decode("utf-8").strip(), i.name.decode("utf-8").strip(),
                          i.username.decode("utf-8").strip(), i.password.decode("utf-8").strip(),
                          i.url.decode("utf-8").strip(), i.group.decode("utf-8").strip(),
                          i.notes.decode("utf-8").strip()))

    return sites

def retrieve_hibp_data(sites):

    for site in sites:
        if site.username is None:
            continue
        username = site.username
        url = BASE_URL + "breachedaccount/{}".format(username)
        response = requests.get(url, headers=HEADERS)
        breaches = response.json()
        print('Checking if the site {} is compromised'.format(site.url))
        for breach in breaches:
            print(breach)
        time.sleep(0.1)


if __name__ == '__main__':
    username, password = get_lastpass_credentials()
    vault = fetch_lastpass_vault(username, password)
    sites = parse_vault(vault)
    retrieve_hibp_data(sites)