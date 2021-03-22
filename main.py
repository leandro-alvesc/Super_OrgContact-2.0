# -*- coding: utf-8 -*-

import os
import flask
from flask_cors import CORS
import requests

import httplib2
import oauth2client.client
import google.oauth2.id_token
import google.auth.transport.requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

DEBUG = True

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.profile', 'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/contacts.readonly'
]
API_SERVICE_NAME = 'people'
API_VERSION = 'v1'


app = flask.Flask(__name__)
app.config.from_object(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'testando123'

# Ativando CORS
CORS(app, resources={r'/*': {'origins': '*'}})


@app.route('/')
def index():
    return print_index_table()


@app.route('/auth/google', methods=['POST'])
def get_contacts():
    request_data = flask.request.get_json()
    auth_code = request_data['code']
    # profile_email = request_data['email']
    # flask.session['profile_email'] = profile_email
    # print(flask.session['profile_email'])

    credentials = oauth2client.client.credentials_from_clientsecrets_and_code(
        CLIENT_SECRETS_FILE,
        SCOPES,
        auth_code
    )

    http_auth = credentials.authorize(httplib2.Http())
    people_api = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, http=http_auth)

    contacts = people_api.people().connections().list(
        resourceName='people/me',
        personFields='names,emailAddresses'
    ).execute()

    emails = extract_contacts(contacts)

    print(emails)

    return flask.jsonify(emails)


@app.route('/contacts')
def all_contacts():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Carregar credenciais
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )

    contacts = googleapiclient.discovery.build(
        API_SERVICE_NAME,
        API_VERSION,
        credentials=credentials
    )

    results = contacts.people().connections().list(
        resourceName='people/me',
        personFields='names,emailAddresses'
    ).execute()

    flask.session['credentials'] = credentials_to_dict(credentials)

    flask.session['contacts'] = extract_contacts(results)

    return flask.jsonify({
        'status': 'success',
        'contacts': flask.session['contacts']
    })


@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('all_contacts'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        clear_credentials()
        return 'Credentials successfully revoked.' + print_index_table()
    else:
        return 'An error occurred.' + print_index_table()


def extract_contacts(flask_contacts):
    dados = [item['emailAddresses'][0] for item in flask_contacts['connections']]
    emails = [dado['value'] for dado in dados]
    dominios = []
    export_contacts = []

    for email in emails:
        if email.split('@')[1] not in dominios:
            dominios.append(email.split('@')[1])

    for dominio in dominios:
        emails_dominio = []
        for email in emails:
            if email.split('@')[1] == dominio:
                emails_dominio.append(email)
        export_contacts.append({'dominio': dominio, 'emails': emails_dominio})
    return export_contacts


def clear_credentials():
    if 'credentials' in flask.session:
        flask.session.pop('credentials', None)
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/contacts">Test an API request</a></td>' +
            '<td>Submit an API request and see a formatted JSON response. ' +
            '    Go through the authorization flow if there are no stored ' +
            '    credentials for the user.</td></tr>' +
            '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
            '<td>Go directly to the authorization flow. If there are stored ' +
            '    credentials, you still might not be prompted to reauthorize ' +
            '    the application.</td></tr>' +
            '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
            '<td>Revoke the access token associated with the current user ' +
            '    session. After revoking credentials, if you go to the test ' +
            '    page, you should see an <code>invalid_grant</code> error.' +
            '</td></tr>' +
            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
            '<td>Clear the access token currently stored in the user session. ' +
            '    After clearing the token, if you <a href="/test">test the ' +
            '    API request</a> again, you should go back to the auth flow.' +
            '</td></tr></table>')


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run()
