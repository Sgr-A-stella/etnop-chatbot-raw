"""Oauth2 register form module for creating new user """
from fastapi.security import OAuth2PasswordRequestForm

from typing import Union

from fastapi.param_functions import Form

# TODO: import from typing when deprecating Python 3.9
from typing_extensions import Annotated

class OAuth2RegisterRequestForm(OAuth2PasswordRequestForm):

    def __init__(
            self,
            grant_type: Annotated[
                str,
                Form(pattern="password"),
            ],
            username: Annotated[
                str,
                Form(),
            ],
            password: Annotated[
                str,
                Form(),
            ],
            scope: Annotated[
                str,
                Form(),
            ] = "",
            client_id: Annotated[
                Union[str, None],
                Form(),
            ] = None,
            client_secret: Annotated[
                Union[str, None],
                Form(),
            ] = None,
            fullname: Annotated[
                str,
                Form(),
            ] = None,
            email: Annotated[
                str,
                Form(),
            ] = None,
    ):
        self.fullname = fullname
        self.email = email
        super().__init__(
            grant_type=grant_type,
            username=username,
            password=password,
            scope=scope,
            client_id=client_id,
            client_secret=client_secret,
        )
