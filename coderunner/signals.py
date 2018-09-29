import os

from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver


@receiver(user_logged_out)
def delete_temp_file_on_logout(sender, user, request, **kwargs):
    """Delete the temp file created
    for the user upon user log out
    """
    fname = request.session.get('file_name', None)
    if fname:
        if os.path.exists(fname):
            print(f'removing {fname}')
            os.remove(fname)
