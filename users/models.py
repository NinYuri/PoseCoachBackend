import datetime, random, string

from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    # create_user - For normal users
    def create_user(self, username, email=None, phone=None, password=None, **extra_fields):
        if not email and not phone:
            raise ValueError('Email o teléfono son obligatorios')
        if not username:
            raise ValueError('Nombre de usuario obligatorio')

        if email:
            email=self.normalize_email(email)

        user=self.model(
            username=username,
            email=email,
            phone=phone,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    # create_superuser - For especial users
    def create_superuser(self, username, email=None, phone=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(username, email, phone, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True, blank=True, null=True)
    phone = models.CharField(max_length = 20, unique = True, blank=True, null=True)
    username = models.CharField(max_length=100, unique=True, blank=False, null=False)
    password = models.CharField(max_length=128, blank=False, null=False)

    date_birth = models.DateField(blank=True, null=True)
    sex = models.CharField(max_length=10, blank=True, null=True, choices=[
        ('M', 'Masculino'),
        ('F', 'Femenino')
    ])
    height = models.IntegerField(null=True, blank=True)
    goal = models.CharField(max_length=50, null=True, blank=True, choices=[
        ('perder_peso', 'Perder peso'),
        ('ganar_musculo', 'Ganar músculo'),
        ('tonificar', 'Tonificar'),
        ('mantener_forma', 'Mantenerme en forma')
    ])
    experience = models.CharField(max_length=50, null=True, blank=True, choices=[
        ('principiante', 'Principiante'),
        ('intermedio', 'Intermedio'),
        ('avanzado', 'Avanzado')
    ])
    equipment = models.CharField(max_length=50, null=True, blank=True, choices=[
        ('mancuernas', 'Mancuernas'),
        ('cuerpo', 'Sólo mi cuerpo'),
        ('bandas', 'Bandas de resistencia'),
        ('gimnasio', 'Máquinas de gimnasio')
    ])

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    otp_code = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    # Evitar conflictos con el modelo de Django
    groups = models.ManyToManyField('auth.Group',
                                    related_name='custom_users_groups',
                                    blank=True,
                                    help_text=('Para evitar conflictos con el modelo de Django'),
                                    related_query_name='user' )

    user_permissions = models.ManyToManyField('auth.Permission',
                                              related_name='custom_users_permissions',
                                              blank=True,
                                              help_text=('Para evitar conflictos con el modelo de Django'),
                                              related_query_name='user')


    @staticmethod
    def create_otp():
        caracteres = string.digits
        return ''.join(random.choice(caracteres) for _ in range(6))

    def otp_valid(self, otp_code):
        if not otp_code:
            return False

        expiration = self.otp_created_at + datetime.timedelta(minutes=10)
        if self.otp_code == otp_code and timezone.now() < expiration:
            return True

        return False