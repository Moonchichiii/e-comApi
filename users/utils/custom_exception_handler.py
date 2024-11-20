import logging
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import status
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.response import Response
from rest_framework.views import exception_handler

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """Custom exception handler for REST framework that handles Django validation errors."""
    if isinstance(exc, DjangoValidationError):
        exc = DRFValidationError(detail=exc.message_dict)

    response = exception_handler(exc, context)
    
    if response is None:
        logger.error("Unhandled exception: %s", exc)
        response = Response(
            {'detail': 'A server error occurred.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    if hasattr(exc, 'get_full_details'):
        response.data['errors'] = exc.get_full_details()
    
    request = context.get('request')
    if request:
        response.data['request_id'] = getattr(request, 'request_id', None)

    return response
