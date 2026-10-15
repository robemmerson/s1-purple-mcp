"""Exceptions for SentinelOne response actions."""


class ResponseError(Exception):
    """Base exception for all response-action errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        """Initialize the exception.

        Args:
            message: The main error message.
            status_code: HTTP status code if applicable.
        """
        self.message = message
        self.status_code = status_code
        super().__init__(message)

    def __str__(self) -> str:
        """Return a string representation of the error."""
        if self.status_code:
            return f"{self.message} (HTTP {self.status_code})"
        return self.message


class ResponseAuthenticationError(ResponseError):
    """The response token was rejected or lacks permission for the action."""


class ResponseAPIError(ResponseError):
    """The management API returned an error."""


class ResponseNetworkError(ResponseError):
    """The management API could not be reached."""
