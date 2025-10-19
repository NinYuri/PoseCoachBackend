import datetime

from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import CustomUser
from users.serializers import UserRegisterInitialSerializer, UserCompleteProfileSerializer, UserLoginSerializer, \
    ForgotPasswordSerializer, ResetPasswordSerializer, ProfileUpdateSerializer
from users.utilities.utils import send_email, send_sms, method


class InitialRegisterView(APIView):
    def post(self, request):
        serializer = UserRegisterInitialSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()

            # OTP Method
            metodo = method(user)

            try:
                if metodo == 'email':
                    send_email(user)
                    message = "Usuario registrado. Por favor, revisa tu correo electrónico"
                elif metodo == 'sms':
                    send_sms(user)
                    message = "Usuario registrado. Por favor, revisa tu teléfono"
                else:
                    return Response({"error": "Se requiere email o teléfono para enviar el OTP"}, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                return Response({"error": f"No se pudo enviar el OTP por {metodo}: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"mensaje": message, "temporal_id": user.id}, status=status.HTTP_200_OK)

        else:
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    def post(self, request):
        temporal_id = request.data.get('temporal_id')
        otp = request.data.get('otp')

        if not temporal_id or not otp:
            return Response({"error": "Se requiere código OTP"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(id=temporal_id, is_active=False)
        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado o ya activado"}, status=status.HTTP_404_NOT_FOUND)

        # Validar código OTP
        if user.otp_code != otp:
            return Response({"error": "El código OTP es incorrecto"}, status=status.HTTP_400_BAD_REQUEST)

        # Validar tiempo
        exp = user.otp_created_at + datetime.timedelta(minutes=10)
        if timezone.now() > exp:
            return Response({
                "error": "Su código OTP ha expirado",
                "sugerencia": "Puedes solicitar un nuevo código OTP",
                "temporal_id": user.id
            }, status=status.HTTP_400_BAD_REQUEST)

        # Limpiar OTP pero no activar todavía
        user.otp_code = None
        user.otp_created_at = None
        user.save()

        return Response({"mensaje": "Código OTP verificado exitosamente"}, status=status.HTTP_200_OK)


class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email', '').strip()
        phone = request.data.get('phone', '').strip()

        if not email and not phone:
            return Response({"error": "Email o teléfono es requerido"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Buscar usuario por email o phone que no esté activado
            if email:
                user = CustomUser.objects.get(email=email, is_active=False)
            else:
                user = CustomUser.objects.get(phone=phone, is_active=False)

        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado o ya activado"}, status=status.HTTP_404_NOT_FOUND)

        # Generar nuevo código OTP
        new_otp = CustomUser.create_otp()
        user.otp_code = new_otp
        user.otp_created_at = timezone.now()
        user.save()

        # Enviar
        metodo = method(user)
        try:
            if metodo == 'email':
                send_email(user)
                message = "Nuevo código OTP enviado a tu correo electrónico"
            elif metodo == 'sms':
                send_sms(user)
                message = "Nuevo código OTP enviado a tu número telefónico"
            else:
                return Response({"error": "No se pudo determinar el método de envío"}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"mensaje": message, "temporal_id": user.id}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"No se pudo enviar el OTP por {metodo}: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CompleteRegisterView(APIView):
    def post(self, request):
        temporal_id = request.data.get('temporal_id')

        if not temporal_id:
            return Response({"error": "ID temporal requerido"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(id=temporal_id, is_active=False)
        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado o ya activado"}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserCompleteProfileSerializer(user, data=request.data)

        if serializer.is_valid():
            serializer.save()

            return Response({"mensaje": "Perfil completado y cuenta activada exitosamente"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token_str = request.data.get('refresh_token')

        if refresh_token_str is None:
            return Response({"error": "Se requiere un refresh token"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token_str)
            token.blacklist()
            return Response({"mensaje": "Log out exitoso"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Ocurrió un error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            return Response({"mensaje": "Enviamos un código OTP para restablecer tu contraseña"}, status=status.HTTP_200_OK)

        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"mensaje": "Contraseña restablecida correctamente"}, status=status.HTTP_200_OK)

        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        # Obtener el usuario autenticado desde el JWT
        user = request.user

        serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            return Response({
                "mensaje": "Perfil actualizado exitosamente",
                "user": ProfileUpdateSerializer(user).data
            }, status=status.HTTP_200_OK)

        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        return self.put(request)


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = ProfileUpdateSerializer(user)

        return Response({"user": serializer.data}, status=status.HTTP_200_OK)