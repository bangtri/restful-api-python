from flask import Flask
from flask_oidc import OpenIDConnect

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
    return 'Hello: ' + str(oidc.user_getfield('name')) + ',  You can logout: <a href="/logout">Log out</a>'


@app.route('/logout')
def logout():
    oidc.logout()
    return 'Hi, you have been logged out! <a href="/">Home</a>'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=1088)
