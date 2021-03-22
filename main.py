import os
import flask
from flask_cors import CORS

import httplib2
import oauth2client.client
import googleapiclient.discovery

from secret_key import SECRET_KEY

DEBUG = True

# Client Secrets File
CLIENT_SECRETS_FILE = "client_secret.json"

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


@app.route('/auth/google', methods=['POST'])
def get_contacts():
    request_data = flask.request.get_json()
    auth_code = request_data['code']

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
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run()
