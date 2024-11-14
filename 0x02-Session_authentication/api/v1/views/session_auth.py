#!/usr/bin/env python3
""" Module for Session Authentication views
"""
from flask import jsonify, request, abort
from api.v1.views import app_views
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def auth_session_login():
    """
    POST /auth_session/login
    Handles login using Session Authentication
    """
    # Retrieve email and password from form data
    email = request.form.get('email')
    password = request.form.get('password')

    # Check if email is provided
    if not email:
        return jsonify({"error": "email missing"}), 400

    # Check if password is provided
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Retrieve user by email
    users = User.search({'email': email})
    if not users or len(users) == 0:
        return jsonify({"error": "no user found for this email"}), 404
    user = users[0]

    # Check if the password is correct
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create a session ID for the User ID
    from api.v1.app import auth  # Import auth here to avoid circular import
    session_id = auth.create_session(user.id)

    # Create the response with the user's JSON representation
    response = jsonify(user.to_json())

    # Set the session ID in a cookie
    session_name = getenv("SESSION_NAME")
    response.set_cookie(session_name, session_id)

    return response
