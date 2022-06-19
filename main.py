import json

import jwt
import users
import requests
from requests.structures import CaseInsensitiveDict
from flask import Flask, jsonify, request
from flask_oidc import OpenIDConnect
from http import HTTPStatus

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'GcVB4c2hvyom7fubilZAO0GOetXhhOf9',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': './client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'cyberid',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_TOKEN_TYPE_HINT': 'access_token'
})
oidc = OpenIDConnect(app)


@app.route('/')
def check_login():
    if oidc.user_loggedin:
        return 'Hello: ' + str(oidc.user_getfield('name')) + ',  You can logout: <a href="/logout">Log out</a>'

    else:
        return 'Hello stranger! Please login :) <a href="/login">Log in</a>'


@app.route('/login')
@oidc.require_login
def login():
    user_info = oidc.user_getinfo(['sub', 'preferred_username', 'email', 'name'], oidc.get_access_token())
    jwt_decode = jwt.decode(oidc.get_access_token(), options={"verify_signature": False})
    print('realm_access', jwt_decode['realm_access'])
    print('resource_access', jwt_decode['resource_access'])
    return user_info


@app.route('/logout')
def logout():
    oidc.logout()
    return 'Hi, you have been logged out! <a href="/">Home</a>'


@app.route('/find-users', methods=['GET'])
def find_users():
    rows = users.find_all_users('SELECT * FROM users')
    data = []
    for r in rows:
        data.append({
            'id': r[0],
            'email': r[1],
            'phone': r[2],
            'firstName': r[3],
            'lastName': r[4]
        })
    return jsonify({'users': data})


@app.route('/access-token', methods=['POST'])
def get_access_token_admin():
    token_endpoint = 'https://stg.accounts.cyberid.vn/auth/realms/cyberid/protocol/openid-connect/token'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    request_body = {
        'client_id': 'python',
        'client_secret': 'GcVB4c2hvyom7fubilZAO0GOetXhhOf9',
        'username': 'manager_user',
        'password': 'Cyberid@1!2@3#4$5%',
        'grant_type': 'password'
    }
    response = requests.post(token_endpoint, data=request_body, headers=headers)
    return response.content


@app.route('/create-user', methods=['POST'])
def create_user():
    access_token = json.loads(get_access_token_admin())['access_token']
    request_data = request.get_data()
    headers = CaseInsensitiveDict()
    headers['Authorization'] = 'Bearer %s' % access_token
    headers['Content-Type'] = 'application/json'
    user_endpoint = 'https://stg.accounts.cyberid.vn/auth/admin/realms/cyberid/users'
    response = requests.post(user_endpoint, data=request_data, headers=headers)
    if response.status_code != HTTPStatus.CREATED:
        return json.loads(response.content)
    else:
        return response.content


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=1088)
