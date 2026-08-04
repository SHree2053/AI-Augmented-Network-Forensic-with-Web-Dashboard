from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

#here this is the form use for creating user on this project
class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']