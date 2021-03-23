import os
import flask
from flask_cors import CORS

import httplib2
import oauth2client.client
import googleapiclient.discovery
from google.cloud import datastore

from secret_key import SECRET_KEY, CLIENT_ID, CLIENT_SECRET

DEBUG = False

# Client Secrets File
CLIENT_SECRETS_FILE = "client_secret.json"

# Datastore Client
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "./datastore_credentials.json"

# Scopes para acesso - Google People API
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.profile', 'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/contacts.readonly'
]
API_SERVICE_NAME = 'people'
API_VERSION = 'v1'

app = flask.Flask(__name__)
app.config.from_object(__name__)

# Secret Key
app.secret_key = SECRET_KEY

# Ativando CORS
CORS(app, resources={r'/*': {'origins': '*'}})

# Instanciar client datastore
datastore_client = datastore.Client()


@app.route('/auth/google', methods=['POST'])
def get_contacts():
    request_data = flask.request.get_json()
    auth_code = request_data['code']

    emails = consume_api(auth_code)

    return emails


@app.route('/revoke/google', methods=['POST'])
def delete_data():
    request_data = flask.request.get_json()
    email_client = request_data['email']

    if email_client == query_datastore(email_client):
        query = datastore_client.query(kind='email')
        query.add_filter('email', '=', email_client)
        results = list(query.fetch())
        datastore_client.delete(results[0].key)

        return f'{email_client} deleted'

    return 'user not found'


@app.route('/update/google', methods=['POST'])
def reload():
    request_data = flask.request.get_json()
    email_client = request_data['email']

    if email_client == query_datastore(email_client):
        query = datastore_client.query(kind='email')
        query.add_filter('email', '=', email_client)
        results = list(query.fetch())
        refresh_token = results[0]['refresh_token']

        creds = oauth2client.client.GoogleCredentials(
            access_token=None,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            refresh_token=refresh_token,
            token_expiry=None,
            token_uri='https://accounts.google.com/o/oauth2/token',
            user_agent=None
        )

        http_auth = creds.authorize(httplib2.Http())
        creds.refresh(http_auth)
        people_api = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, http=http_auth)

        contacts = people_api.people().connections().list(
            resourceName='people/me',
            personFields='names,emailAddresses'
        ).execute()

        emails = extract_contacts(contacts)

        return flask.jsonify(emails)

    return 'none'


@app.route('/')
def index():
    return 'Para acessar a API: /auth/google'


def consume_api(auth_code):
    credentials = oauth2client.client.credentials_from_clientsecrets_and_code(
        CLIENT_SECRETS_FILE,
        SCOPES,
        auth_code
    )

    kind = 'email'
    task_key = datastore_client.key(kind)
    email_client = credentials.id_token['email']
    name_client = credentials.id_token['name']

    if email_client != query_datastore(email_client):
        task = datastore.Entity(key=task_key)
        task['name'] = name_client
        task['email'] = email_client
        task['refresh_token'] = credentials.refresh_token
        datastore_client.put(task)

    http_auth = credentials.authorize(httplib2.Http())
    people_api = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, http=http_auth)

    contacts = people_api.people().connections().list(
        resourceName='people/me',
        personFields='names,emailAddresses'
    ).execute()

    emails = extract_contacts(contacts)

    return flask.jsonify(emails)


def query_datastore(email):
    query = datastore_client.query(kind='email')
    query.add_filter('email', '=', email)
    results = list(query.fetch())
    if results:
        return results[0]['email']
    return 'not found'


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


if __name__ == '__main__':
    # Para rodar localmente - Retirar ao executar no servidor
    # os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run()
