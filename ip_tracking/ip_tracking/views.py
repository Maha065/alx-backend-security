from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from ratelimit.decorators import ratelimit

@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
def login_view(request):
    """
    A simple login view with rate limiting:
    - Authenticated users: 10 requests/min
    - Anonymous users: 5 requests/min
    """

    # Determine rate dynamically
    if request.user.is_authenticated:
        rate = '10/m'
    else:
        rate = '5/m'

    # Apply dynamic rate limiting
    limiter = ratelimit(key='user_or_ip', rate=rate, method='POST', block=True)
    view = limiter(_login_handler)
    return view(request)


def _login_handler(request):
    """Actual login handler logic."""
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return HttpResponse("Login successful.")
        else:
            return HttpResponse("Invalid credentials.", status=401)
    return render(request, 'login.html')
