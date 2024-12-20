#!/usr/bin/env python3
"""Class SessionAuth that inherits from Auth"""

from api.v1.auth.auth import Auth
from models.user import User
import uuid


class SessionAuth(Auth):
    """SessionAuth class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a session ID for a user_id"""
        if user_id is None or not isinstance(user_id, str):
            return None
        # generate a session ID
        session_id = str(uuid.uuid4())

        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Return a User ID based on a Session ID"""
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Return a User instance based on a cookie value"""
        session_id = self.session_cookie(request)
        if session_id is None:
            return None
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return None
        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Deletes the user session based on a cookie value
        """
        if request is None:
            return False

        # Retrieve session ID from the request's cookies
        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        # Check if session ID is mapped to a User ID
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False

        # Delete the session ID from user_id_by_session_id dictionary
        del self.user_id_by_session_id[session_id]
        return True
