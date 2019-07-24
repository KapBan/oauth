from .helpers import OAuthTransport
from .settings import CLIENT_ID, CLIENT_SCOPE, CLIENT_SECRET, RESOURCE_SERVER_URL
from .exceptions import OAuthValidationException

try:
    transport = OAuthTransport(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        client_scope=CLIENT_SCOPE
    )
except OAuthValidationException as e:
    print(e)
else:
    response = transport.get(
        url=RESOURCE_SERVER_URL
    )

    if response.status_code == 200:
        data = response.json()

