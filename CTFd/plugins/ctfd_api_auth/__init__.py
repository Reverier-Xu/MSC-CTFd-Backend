import functools
import json
from flask import request, session, url_for
from flask_restplus import Namespace, Resource

from CTFd.models import Users, db
from CTFd.plugins import bypass_csrf_protection
from CTFd.utils import validators, config, email, get_app_config, get_config, user as current_user
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.crypto import verify_password
from CTFd.utils.decorators import ratelimit
from CTFd.utils.security.auth import login_user, logout_user


def load(app):
    def ret_json(func):
        @functools.wraps(func)
        def _ret_json(*args, **kwargs):
            return json.dumps(func(*args, **kwargs))

        return _ret_json

    @app.route('/api/v1/login', methods=['POST'])
    @ratelimit(method="POST", limit=10, interval=5)
    @bypass_csrf_protection
    @ret_json
    def login():  # login
        req = request.json
        if 'name' not in req or 'password' not in req:
            return {"success": False, "data": None}
        name = req['name']
        if validators.validate_email(name) is True:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(name=name).first()
        if user and verify_password(request.json["password"], user.password):
            session.regenerate()
            login_user(user)
            db.session.close()
            return {
                "success": True, "data": {
                "nonce": session["nonce"],
            }}
        else:
            db.session.close()
            return {"success": False, "data": "Your username or password is incorrect"}

    @app.route('/api/v1/logout')
    @ratelimit(method="GET", limit=10, interval=5)
    @ret_json
    def logout():
        if current_user.authed():
            logout_user()
        return {"success": True, "data": None}

    @app.route('/api/v1/register', methods=['POST'])
    @ratelimit(method="POST", limit=10, interval=5)
    @bypass_csrf_protection
    @ret_json
    def register():  # register
        def error(msg):
            return {"success": False, "data": msg}

        name = request.json.get("name", "").strip()
        email_address = request.json.get("email", "").strip().lower()
        password = request.json.get("password", "").strip()

        name_len = len(name) == 0
        names = Users.query.add_columns(
            "name", "id").filter_by(name=name).first()
        emails = (
            Users.query.add_columns("email", "id")
                .filter_by(email=email_address)
                .first()
        )
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = validators.validate_email(email_address)
        team_name_email_check = validators.validate_email(name)

        if not valid_email:
            return error("Please enter a valid email address")
        if email.check_email_is_whitelisted(email_address) is False:
            return error("Only email addresses under {domains} may register".format(
                domains=get_config("domain_whitelist")
            ))
        if names:
            return error("That user name is already taken")
        if team_name_email_check is True:
            return error("Your user name cannot be an email address")
        if emails:
            return error("That email has already been used")
        if pass_short:
            return error("Pick a longer password")
        if pass_long:
            return error("Pick a shorter password")
        if name_len:
            return error("Pick a longer user name")

        with app.app_context():
            user = Users(name=name, email=email_address, password=password)
            db.session.add(user)
            db.session.commit()
            db.session.flush()
            login_user(user)
            if config.can_send_mail() and get_config(
                    "verify_emails"
            ):
                email.verify_email_address(user.email)
                db.session.close()
                return {"success": True, "data": url_for("auth.confirm")}
            else:
                if (config.can_send_mail()):
                    email.successful_registration_notification(user.email)
        db.session.close()
        return {"success": True, "data": None}