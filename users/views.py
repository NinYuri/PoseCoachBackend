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
from users.utilities.profile_utils import save_temp_change, get_temp_change, clear_temp_change
from users.utilities.utils import send_email, send_sms, method, forgot_password_email, forgot_password_sms, add_email, \
    change_email, add_sms, change_sms, resend_email, resend_sms


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


class CheckUsernameView(APIView):
    def post(self, request):
        username = request.data.get('username', '').strip()

        if not username:
            return Response({"available": False, "error": "El usuario es requerido"}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(username=username).exists():
            return Response({"available": False, "mensaje": "Este nombre de usuario ya está en uso"}, status=status.HTTP_200_OK)

        return Response({"available": True}, status=status.HTTP_200_OK)


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
            return Response({"mensaje": "¡Nos vemos después!"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Ocurrió un error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data["user"]
            return Response({"mensaje": "Enviamos un código OTP para restablecer tu contraseña", "otp": user.otp_code}, status=status.HTTP_200_OK)

        else:
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"mensaje": "Contraseña restablecida correctamente"}, status=status.HTTP_200_OK)

        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class ResendOTPPassView(APIView):
    def post(self, request):
        email = request.data.get('email', '').strip()
        phone = request.data.get('phone', '').strip()

        if not email and not phone:
            return Response({"error": "Debes proporcionar un email o número de teléfono"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if email:
                user = CustomUser.objects.get(email=email, is_active=True)
            else:
                user = CustomUser.objects.get(phone=phone, is_active=True)

        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND)

        # Generar nuevo OTP
        new_otp = CustomUser.create_otp()
        user.otp_code = new_otp
        user.otp_created_at = timezone.now()
        user.save()

        # Metodo de envio
        metodo = method(user)
        try:
            if metodo == 'email':
                forgot_password_email(user)
                mensaje = "Nuevo código OTP enviado a tu correo electrónico."
            elif metodo == 'sms':
                forgot_password_sms(user)
                mensaje = "Nuevo código OTP enviado a tu número telefónico."
            else:
                return Response({"error": "No se pudo determinar el método de envío"}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"mensaje": mensaje, "otp": user.otp_code}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"No se pudo enviar el OTP por {metodo}: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        # Obtener el usuario autenticado desde el JWT
        user = request.user

        serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()

            return Response({"mensaje": "Perfil actualizado exitosamente" }, status=status.HTTP_200_OK)

        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        return self.put(request)


# ENDPOINT: Añadir email
class AddEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        new_email = request.data.get('email', '').strip()

        if not new_email:
            return Response({"error": "Debes escribir un nuevo email"}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=new_email, is_active=True).exists():
            return Response({"error": "Lo siento, este correo ya está en uso"}, status=status.HTTP_400_BAD_REQUEST)

        otp = CustomUser.create_otp()
        otp_time = timezone.now()

        # Guardar en cache
        save_temp_change(
            user_id=user.id,
            email=new_email,
            otp=otp,
            otp_time=otp_time,
        )

        add_email(user, new_email, otp)

        return Response({"mensaje": "Código OTP enviado al nuevo correo electrónico"}, status=status.HTTP_200_OK)


# ENDPOINT: Cambiar email
class ChangeEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.email:
            return Response({"error": "No tienes un correo registrado"}, status=status.HTTP_400_BAD_REQUEST)

        new_email = request.data.get('email', '').strip()
        if not new_email:
            return Response({"error": "Debes escribir un nuevo correo electrónico"}, status=status.HTTP_400_BAD_REQUEST)

        if new_email == user.email:
            return Response({"error": "El nuevo correo debe ser diferente al anterior"}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=new_email).exclude(id=user.id).exists():
            return Response({"error": "Lo siento, este correo ya está en uso"}, status=400)

        otp = CustomUser.create_otp()
        otp_time = timezone.now()
        save_temp_change(
            user.id,
            email=new_email,
            otp=otp,
            otp_time=otp_time
        )

        change_email(user, new_email, otp)
        return Response({"mensaje": "Código OTP enviado al nuevo correo electrónico"}, status=status.HTTP_200_OK)


# ENDPOINT: Verificar OTP
class VerifyEmailOtpView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        otp = request.data.get("otp", "")

        temp = get_temp_change(user.id)
        if not temp:
            return Response({"error": "No hay proceso en curso o expiró"}, status=400)

        if otp != temp.get("otp"):
            return Response({"error": "El código OTP es incorrecto"}, status=400)

        if timezone.now() > temp["otp_time"] + datetime.timedelta(minutes=10):
            return Response({"error": "El código OTP ha expirado"}, status=400)

        # Aplicar cambio real
        new_email = temp.get("email")
        if new_email:
            user.email = new_email
            user.save()

        clear_temp_change(user.id)

        return Response({"mensaje": "Correo electrónico verificado y actualizado"}, status=200)


# ENDPOINT: Añadir phone
class AddPhoneView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        new_phone = request.data.get('phone', '').strip()

        if not new_phone:
            return Response({"error": "Debes escribir un nuevo teléfono"}, status=400)

        if CustomUser.objects.filter(phone=new_phone).exists():
            return Response({"error": "Este número telefónico ya está en uso"}, status=400)

        otp = CustomUser.create_otp()
        otp_time = timezone.now()

        save_temp_change(user.id, phone=new_phone, otp=otp, otp_time=otp_time)
        add_sms(user, new_phone, otp)

        return Response({"mensaje": "Código OTP enviado al nuevo número telefónico"}, status=200)


# ENDPOINT: Cambiar phone
class ChangePhoneView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        if not user.phone:
            return Response({"error": "No tienes un número telefónico registrado"}, status=400)

        new_phone = request.data.get("phone", "").strip()
        if not new_phone:
            return Response({"error": "Debes escribir un nuevo número telefónico"}, status=400)

        if new_phone == user.phone:
            return Response({"error": "El nuevo número telefónico debe ser diferente al anterior"}, status=400)

        if CustomUser.objects.filter(phone=new_phone).exclude(id=user.id).exists():
            return Response({"error": "Lo siento, este número telefónico ya está en uso"}, status=400)

        otp = CustomUser.create_otp()
        otp_time = timezone.now()

        save_temp_change(user.id, phone=new_phone, otp=otp, otp_time=otp_time)
        change_sms(user, new_phone, otp)

        return Response({"mensaje": "Código OTP enviado al nuevo número telefónico"}, status=200)


# ENDPOINT: Verificar OTP
class VerifyPhoneOtpView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        otp = request.data.get("otp", "")

        temp = get_temp_change(user.id)
        if not temp:
            return Response({"error": "No hay proceso en curso o expiró"}, status=400)

        if otp != temp.get("otp"):
            return Response({"error": "El código OTP es incorrecto"}, status=400)

        if timezone.now() > temp["otp_time"] + datetime.timedelta(minutes=10):
            return Response({"error": "El código OTP ha expirado"}, status=400)

        # Aplicar cambio real
        new_phone = temp.get("phone")
        if new_phone:
            user.phone = new_phone
            user.save()

        clear_temp_change(user.id)

        return Response({"mensaje": "Número telefónico verificado y actualizado"}, status=200)


# ENDPOINT: Reenviar OTP
class ResendOtpProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        temp = get_temp_change(user.id)
        if not temp:
            return Response({"error": "No hay cambio en proceso"}, status=400)

        otp = CustomUser.create_otp()
        otp_time = timezone.now()

        # Actualizar cache
        save_temp_change(
            user.id,
            email=temp.get("email"),
            phone=temp.get("phone"),
            otp=otp,
            otp_time=otp_time
        )

        if temp.get("email"):
            resend_email(user, temp["email"], otp)
        if temp.get("phone"):
            resend_sms(user, temp["phone"], otp)

        return Response({"mensaje": "Nuevo código OTP enviado exitosamente"}, status=200)


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = ProfileUpdateSerializer(user)

        return Response({"user": serializer.data}, status=status.HTTP_200_OK)


class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user

        username = user.username
        user.delete()

        return Response(
            {"mensaje": f"La cuenta de {username} ha sido eliminada exitosamente."},
            status=status.HTTP_200_OK
        )