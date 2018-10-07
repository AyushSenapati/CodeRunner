from django import forms
from django.contrib.auth.forms import (UserCreationForm,
                                       AuthenticationForm,
                                       SetPasswordForm,
                                       PasswordChangeForm)
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
        validators=[validate_email_unique, ],
        # widget=forms.TextInput(attrs={
        #                        'class': 'form-control'
        #                        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Username'})

        self.fields['email'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Email'})

        self.fields['password1'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Password'})

        self.fields['password2'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Re-enter Password'})

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', )
        # widgets = {
        #     'email': forms.TextInput(attrs={
        #                              'class': 'class_signup_form',
        #                              'id': 'id_signup_form'
        #                              })
        # }


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Username'})
        self.fields['password'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Password'})

    class Meta:
        model = User
        fields = ('username', 'password')


class CustomPasswordResetForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['new_password1'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'New password'})
        self.fields['new_password2'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Confirm password'})

    class Meta:
        model = User
        fields = ('password1', 'password2')


class CustomPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['old_password'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Old password'})
        self.fields['new_password1'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'New password'})
        self.fields['new_password2'].widget.attrs.update(
            {'class': 'form-control', 'placeholder': 'Confirm new password'})

    class Meta:
        model = User
        fields = ('password', 'password1', 'password2')
