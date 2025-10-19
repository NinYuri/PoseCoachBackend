import vonage
from django.conf import settings
from django.core.mail import send_mail


def send_email(usr):
    asunto = "OTP PoseCoach"
    message = f"""
    Tu código de verificación es: {usr.otp_code}
    Este código expira en 10 minutos. 
        
    No lo compartas con nadie por seguridad.
        
    Atentamente,
    PoseCoach ❤️
    """

    send_mail(
        subject=asunto,
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[usr.email],
        fail_silently=False
    )

def forgot_password_email(usr):
    asunto = "Restablecimiento de Contraseña"
    message = f"""
    Hola {usr.username}

    Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.
    Tu código de verificación (OTP) es: {usr.otp_code}

    Este código es válido por 10 minutos. 
    Si no solicitaste un restablecimiento de contraseña, ignora este mensaje.

    Atentamente,  
    PoseCoach ❤️
    """

    send_mail(
        subject=asunto,
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[usr.email],
        fail_silently=False
    )


def send_sms(usr):
    try:
        # Inicializar cliente Vonage
        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        sms = vonage.Sms(client)

        # Crear mensaje
        message = f"""
        Tu codigo de verificacion es: {usr.otp_code}
        Este codigo expira en 10 minutos. 
        
        No lo compartas con nadie por seguridad.
        
        Atte.
        PoseCoach ❤
        """

        # Enviar SMS
        response = sms.send_message({
            'from': settings.VONAGE_FROM_NUMBER,
            'to': usr.phone,
            'text': message
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def forgot_password_sms(usr):
    try:
        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        sms = vonage.Sms(client)

        # Crear mensaje
        message = f"""
        Hola {usr.username}

        Hemos recibido una solicitud para restablecer la contrasena de tu cuenta.
        Tu codigo de verificacion (OTP) es: {usr.otp_code}

        Este codigo es valido por 10 minutos. 
        Si no solicitaste un restablecimiento de contrasena, ignora este mensaje.

        Atentamente,  
        PoseCoach ❤
        """

        # Enviar SMS
        response = sms.send_message({
            'from': settings.VONAGE_FROM_NUMBER,
            'to': usr.phone,
            'text': message
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return False


def method(usr):
    if usr.email and usr.email.strip():
        return 'email'
    elif usr.phone and usr.phone.strip():
        return 'sms'
    else:
        return None