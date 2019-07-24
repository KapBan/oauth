class OAuthValidationException(Exception):
    """Raised in case of wrong credentials committed to OAuth"""
    def __init__(self, message, **kwargs):
        self.message = message
        self.payload = {
            **kwargs,
            'message': self.message
        }

    def __str__(self):
        return str(
            self.payload
        )
