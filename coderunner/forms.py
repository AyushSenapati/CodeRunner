from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


def validate_email_unique(email):
    """Check if provided
    email address has already been registered
    """

    exists = User.objects.filter(email=email)
    if exists:
        raise forms.ValidationError("Email already been registered")


class SignUpForm(UserCreationForm):
    """Sign up form to extend with email field"""

    email = forms.EmailField(
        max_length=234,
        required=True,
        help_text="Required. Enter a valid email address",
        validators=[validate_email_unique, ]
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', )
