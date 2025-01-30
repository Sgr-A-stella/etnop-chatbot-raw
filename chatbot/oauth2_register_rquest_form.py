"""

"""
from fastapi.security import OAuth2PasswordRequestForm

from typing import Any, Dict, List, Optional, Union, cast

from fastapi.exceptions import HTTPException
from fastapi.openapi.models import OAuth2 as OAuth2Model
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.param_functions import Form
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

# TODO: import from typing when deprecating Python 3.9
from typing_extensions import Annotated, Doc

class OAuth2RegisterRequestForm(OAuth2PasswordRequestForm):

    def __init__(
            self,
            grant_type: Annotated[
                str,
                Form(pattern="password"),
                Doc(
                    """
                    The OAuth2 spec says it is required and MUST be the fixed string
                    "password". This dependency is strict about it. If you want to be
                    permissive, use instead the `OAuth2PasswordRequestForm` dependency
                    class.
                    """
                ),
            ],
            username: Annotated[
                str,
                Form(),
                Doc(
                    """
                    `username` string. The OAuth2 spec requires the exact field name
                    `username`.
                    """
                ),
            ],
            password: Annotated[
                str,
                Form(),
                Doc(
                    """
                    `password` string. The OAuth2 spec requires the exact field name
                    `password`.
                    """
                ),
            ],
            scope: Annotated[
                str,
                Form(),
                Doc(
                    """
                    A single string with actually several scopes separated by spaces. Each
                    scope is also a string.
    
                    For example, a single string with:
    
                    ```python
                    "items:read items:write users:read profile openid"
                    ````
    
                    would represent the scopes:
    
                    * `items:read`
                    * `items:write`
                    * `users:read`
                    * `profile`
                    * `openid`
                    """
                ),
            ] = "",
            client_id: Annotated[
                Union[str, None],
                Form(),
                Doc(
                    """
                    If there's a `client_id`, it can be sent as part of the form fields.
                    But the OAuth2 specification recommends sending the `client_id` and
                    `client_secret` (if any) using HTTP Basic auth.
                    """
                ),
            ] = None,
            client_secret: Annotated[
                Union[str, None],
                Form(),
                Doc(
                    """
                    If there's a `client_password` (and a `client_id`), they can be sent
                    as part of the form fields. But the OAuth2 specification recommends
                    sending the `client_id` and `client_secret` (if any) using HTTP Basic
                    auth.
                    """
                ),
            ] = None,
            fullname: Annotated[
                str,
                Form(),
                Doc(
                    """
                    `fullname` string. The chatbot register function requires the exact field name
                    `fullname`.
                    """
                ),
            ] = None,
            email: Annotated[
                str,
                Form(),
                Doc(
                    """
                    `email` string. The chatbot register requires the exact field name
                    `email`.
                    """
                ),
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
