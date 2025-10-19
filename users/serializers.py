from datetime import timedelta

from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import CustomUser
from users.utilities.utils import method, forgot_password_email, forgot_password_sms


class UserRegisterInitialSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        required=True,
        allow_blank=False,
        error_messages={
            'blank': 'La contraseña no puede estar vacía',
            'min_length': 'La contraseña debe tener al menos 8 caracteres'
        }
    )

    confirm_password = serializers.CharField(
        write_only=True,
        required=True,
        allow_blank=False,
        error_messages={
            'blank': 'Debes confirmar tu contraseña'
        }
    )

    email = serializers.EmailField(
        required=False,
        allow_blank=True,
        validators=[
            UniqueValidator(
                queryset=CustomUser.objects.all(),
                message="El correo electrónico ya está registrado"
            )
        ]
    )

    phone = serializers.CharField(
        required=False,
        allow_blank=True,
        validators=[
            UniqueValidator(
                queryset=CustomUser.objects.all(),
                message="El número telefónico ya está registrado"
            )
        ]
    )

    class Meta:
        model = CustomUser
        fields = ['email', 'phone', 'password', 'confirm_password']

    def validate(self, data):
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()

        if not email and not phone:
            raise serializers.ValidationError('Email o teléfono es requerido')

        if not password:
            raise serializers.ValidationError('La contraseña no puede estar vacía')

        if not confirm_password:
            raise serializers.ValidationError('Debes confirmar tu contraseña')

        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Las contraseñas no coinciden")

        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')

        if 'email' in validated_data and validated_data['email'] == '':
            validated_data['email'] = None
        if 'phone' in validated_data and validated_data['phone'] == '':
            validated_data['phone'] = None

        # Temporal username
        base_username = validated_data.get('email', '').split('@')[0] if validated_data.get('email') else f"user_{validated_data.get('phone')}"
        temp_username = base_username
        counter = 1

        while CustomUser.objects.filter(username=temp_username).exists():
            temp_username = f"{temp_username}_{counter}"
            counter += 1

        otp = CustomUser.create_otp()

        user = CustomUser.objects.create_user(
            username = temp_username,
            **validated_data,
            is_active = False,
            otp_code = otp,
            otp_created_at=timezone.now()
        )
        user.set_password(password)
        user.save()

        return user


class UserCompleteProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        validators=[
            UniqueValidator(
                queryset=CustomUser.objects.all(),
                message="Este nombre de usuario ya está en uso"
            )
        ]
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'date_birth', 'sex', 'height', 'goal', 'experience', 'equipment']

    def validate(self, data):
        required_fields = ['username', 'date_birth', 'sex', 'height', 'goal', 'experience', 'equipment']
        for field in required_fields:
            if field not in data or not data[field]:
                raise serializers.ValidationError(f"El campo {field} es requerido")

        return data

    def update(self, instance, validated_data):
        # Actualizar usuario con los datos del perfil
        instance.username = validated_data.get('username', instance.username)
        instance.date_birth = validated_data.get('date_birth', instance.date_birth)
        instance.sex = validated_data.get('sex', instance.sex)
        instance.height = validated_data.get('height', instance.height)
        instance.goal = validated_data.get('goal', instance.goal)
        instance.experience = validated_data.get('experience', instance.experience)
        instance.equipment = validated_data.get('equipment', instance.equipment)
        instance.is_active = True
        instance.save()
        return instance


class UserLoginSerializer(serializers.Serializer):
    identificador = serializers.CharField(
        write_only=True,
        required=True,
        allow_blank=False,
        trim_whitespace=True,
        error_messages={
            'required': 'El usuario es obligatorio',
            'blank': 'El usuario no puede estar vacío'
        }
    )

    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
        required=True,
        allow_blank=False,
        trim_whitespace=True,
        error_messages={
            'required': 'La contraseña es obligatoria',
            'blank': 'La contraseña no puede estar vacía'
        }
    )

    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    user = serializers.SerializerMethodField(read_only=True)

    def validate(self, attrs):
        identificador = attrs.get('identificador')
        password = attrs.get('password')

        errors = {}

        if not identificador:
            errors['identificador'] = 'El identificador no puede estar vacío'
        if not password:
            errors['password'] = 'La contraseña no puede estar vacía'

        if errors:
            raise serializers.ValidationError(errors)

        user = None

        # Autenticar por username
        user = authenticate(username=identificador, password=password)

        # Si no funciona, intentar por email
        if user is None:
            try:
                user_obj = CustomUser.objects.get(email=identificador)
                user = authenticate(username=user_obj.username, password=password)
            except CustomUser.DoesNotExist:
                user = None

        # Si no funciona, intentar por phone
        if user is None:
            try:
                user_obj = CustomUser.objects.get(phone=identificador)
                user = authenticate(username=user_obj.username, password=password)
            except CustomUser.DoesNotExist:
                user = None

        if user is None:
            raise serializers.ValidationError({"error": "Credenciales inválidas"})

        if not user.is_active:
            raise serializers.ValidationError({"error": "La cuenta no está activada. Por favor, verifica tu cuenta."})

        # Generar tokens JWT
        refresh = RefreshToken.for_user(user)

        return {
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'phone': user.phone,
                'is_active': user.is_active,
            }
        }

    def get_user(self, obj):
        return obj.get('user')


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)

    def validate(self, attrs):
        email = attrs.get('email')
        phone = attrs.get('phone')

        if not email and not phone:
            raise serializers.ValidationError("Debes proporcionar tu email o número telefónico")

        try:
            if email:
                user = CustomUser.objects.get(email=email)
            else:
                user = CustomUser.objects.get(phone=phone)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Usuario no encontrado")

        otp = CustomUser.create_otp()
        user.otp_code = otp
        user.otp_created_at = timezone.now()
        user.save()

        # OTP Method
        metodo = method(user)

        try:
            if metodo == 'email':
                forgot_password_email(user)
                message = "Enviamos un código de verificación a tu correo. Revísalo y escríbelo aquí para continuar"
            elif metodo == 'sms':
                forgot_password_sms(user)
                message = "Enviamos un código de verificación a tu teléfono. Revísalo y escríbelo aquí para continuar"
        except Exception as e:
            raise serializers.ValidationError(f"No se pudo enviar código OTP: {str(e)}")

        attrs["user"] = user
        return user


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)
    otp = serializers.CharField()

    new_password = serializers.CharField(
        write_only=True,
        required=True,
        allow_blank=False,
        error_messages={
            'blank': 'La nueva contraseña no puede estar vacía'
        }
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        allow_blank=False,
        error_messages={
            'blank': 'Debe confirmar su contraseña'
        }
    )

    def validate(self, attrs):
        email = attrs.get('email')
        phone = attrs.get('phone')
        otp = attrs.get('otp')
        new_password = attrs.get('new_password', '').strip()
        new_password_confirm = attrs.get('new_password_confirm', '').strip()

        if not email and not phone:
            raise serializers.ValidationError("Debes escribir tu email o teléfono")

        if not otp:
            raise serializers.ValidationError("Debes escribir el código OTP que te enviamos")

        if not new_password:
            raise serializers.ValidationError("La nueva contraseña no puede estar vacía")
        if not new_password_confirm:
            raise serializers.ValidationError("Debe confirmar su contraseña")

        try:
            if email:
                user = CustomUser.objects.get(email=email)
            else:
                user = CustomUser.objects.get(phone=phone)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Usuario no encontrado")

        if user.otp_code != otp:
            raise serializers.ValidationError("Código OTP incorrecto")

        expires = user.otp_created_at + timedelta(minutes=10)
        if timezone.now() > expires:
            raise serializers.ValidationError("El código OTP ha expirado")

        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError("Las contraseñas no coinciden")

        attrs["user"] = user
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        user.password = make_password(self.validated_data['new_password'])
        user.otp_code = None
        user.save()
        return user


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [ 'email', 'phone', 'username', 'date_birth', 'sex', 'height', 'goal', 'experience', 'equipment' ]
        extra_kwargs = {
            'email': {'required': False},
            'phone': {'required': False},
            'username': {'required': False},
            'date_birth': {'required': False},
            'sex': {'required': False},
            'height': {'required': False},
            'goal': {'required': False},
            'experience': {'required': False},
            'equipment': {'required': False}
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Remover validadores automáticos de unicidad
        for field_name in ['email', 'phone', 'username']:
            if field_name in self.fields:
                self.fields[field_name].validators = [
                    val for val in self.fields[field_name].validators
                    if not hasattr(val, 'queryset')
                ]

    def validate(self, attrs):
        errors = {}

        # Verificar que los campos no sean iguales
        for field, new_value in attrs.items():
            current_value = getattr(self.instance, field)

            if current_value == new_value:
                field_names = {
                    'email': 'email',
                    'phone': 'teléfono',
                    'username': 'usuario',
                    'date_birth': 'fecha de nacimiento',
                    'sex': 'género',
                    'height': 'altura',
                    'goal': 'objetivo',
                    'experience': 'experiencia',
                    'equipment': 'equipo'
                }
                errors[field] = f"El nuevo {field_names.get(field, field)} debe ser distinto al actual"

        # Validaciones de unicidad
        if 'email' in attrs and attrs['email'] != getattr(self.instance, 'email', None):
            if CustomUser.objects.exclude(id=self.instance.id).filter(email=attrs['email']).exists():
                errors['email'] = "Este email ya está en uso"

        if 'phone' in attrs and attrs['phone'] != getattr(self.instance, 'phone', None):
            if CustomUser.objects.exclude(id=self.instance.id).filter(phone=attrs['phone']).exists():
                errors['phone'] = "Este teléfono ya está en uso"

        if 'username' in attrs and attrs['username'] != getattr(self.instance, 'username', None):
            if CustomUser.objects.exclude(id=self.instance.id).filter(username=attrs['username']).exists():
                errors['username'] = "Este nombre de usuario ya está en uso"

        if errors:
            raise serializers.ValidationError(errors)
        return attrs

    def update(self, instance, validated_data):
        # Filtrar solo los campos que cambiaron
        changed_data = {}
        for attr, value in validated_data.items():
            current_value = getattr(instance, attr)
            if current_value != value:
                changed_data[attr] = value

        if not changed_data:
            return instance

        for attr, value in changed_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance