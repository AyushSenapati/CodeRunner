import os

from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver

import logging

logger = logging.getLogger(__name__)


@receiver(user_logged_out)
def delete_temp_file_on_logout(sender, user, request, **kwargs):
    """Delete the temp file created
    for the user upon user log out
    """
    fname = request.session.get('file_name', None)
    if fname:
        if os.path.exists(fname):
            logger.info(f'removing {fname} for user: {user}')
            os.remove(fname)
