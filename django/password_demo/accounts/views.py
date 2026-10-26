from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.shortcuts import render


def page(request, message="", status=200, error=False, stored_hash=""):
    """Render the demo page with the forms and an optional result message."""
    return render(
        request,
        "accounts/home.html",
        {"message": message, "error": error, "stored_hash": stored_hash},
        status=status,
    )


def register(request):
    if request.method != "POST":
        return page(request)

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    if not username or not password:
        return page(request, "Username and password are required.", 400, True)

    if User.objects.filter(username=username).exists():
        return page(request, "Username already exists.", 400, True)

    try:
        validate_password(password, user=User(username=username))
    except ValidationError as error:
        return page(request, "; ".join(error.messages), 400, True)

    user = User.objects.create_user(
        username=username,
        password=password
    )

    # Demo only: show the stored hash so you can see that the plain
    # password is never saved.
    return page(request, "User registered successfully!", stored_hash=user.password)


def user_login(request):
    if request.method != "POST":
        return page(request)

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    user = authenticate(request, username=username, password=password)

    if user is None:
        # Same message for unknown user and wrong password, so the
        # response does not reveal which usernames exist.
        return page(request, "Invalid username or password.", 401, True)

    login(request, user)
    return page(request, f"Welcome, {user.username}!")


def user_logout(request):
    if request.method != "POST":
        return page(request)

    logout(request)
    return page(request, "Logged out successfully.")
