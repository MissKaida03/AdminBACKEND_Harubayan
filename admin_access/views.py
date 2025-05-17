import random
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from .models import AdminUser
from .serializers import LoginSerializer, OTPVerifySerializer
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie

@ensure_csrf_cookie
def get_csrf_token(request):
    return JsonResponse({'message': 'CSRF cookie set'})


# ✅ Ensures frontend can fetch CSRF token
@method_decorator(ensure_csrf_cookie, name='dispatch')
class GetCSRFTokenView(APIView):
    def get(self, request):
        return Response({'message': 'CSRF cookie set'}, status=200)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                otp = f"{random.randint(100000, 999999)}"
                user.otp_code = otp
                user.is_verified = False
                user.save()

                send_mail(
                    'Your HaruBayan OTP Code',
                    f'Your OTP code is: {otp}',
                    'harubayan.official@gmail.com',  # sender email
                    [user.email],
                    fail_silently=False,
                )

                login(request, user)  # session login

                return Response({'message': 'OTP sent to email.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OTPVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            print("Is user authenticated?", request.user.is_authenticated)
            print("User:", request.user)
            
            serializer = OTPVerifySerializer(data=request.data)
            if serializer.is_valid():
                otp = serializer.validated_data['otp_code']
                user = request.user
                print(f"User OTP: {user.otp_code}, Received OTP: {otp}")
                if user.otp_code == otp:
                    user.is_verified = True
                    user.save()
                    return Response({'message': 'Login successful!', 'role': user.role}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                print("Serializer errors:", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print("Exception in OTPVerifyView:", str(e))
            return Response({'error': 'Server error during OTP verification', 'details': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
