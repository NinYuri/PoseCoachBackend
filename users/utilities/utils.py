import vonage
from django.conf import settings
from django.contrib.messages.context_processors import messages
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

def add_email(usr, new_email, otp):
    asunto = "Añadir Correo Electrónico"
    message = f"""
    Hola {usr.username},
    
    Tu código de verificación es: {otp}
    Este código expira en 10 minutos. 

    No lo compartas con nadie por seguridad.

    Atentamente,
    PoseCoach ❤️
    """

    send_mail(
        subject=asunto,
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[new_email],
        fail_silently=False
    )

def change_email(usr, new_email, otp):
    asunto = "Confirmación de cambio de correo"
    message = f"""
    Hola {usr.username},
    
    Hemos recibido una solicitud para cambiar el correo asociado a tu cuenta.
    Tu código de verificación es: {otp}
    
    Este código es válido por 10 minutos.
    Si no realizaste esta solicitud, ignora este mensaje.
    
    Atentamente,
    PoseCoach ❤️
    """

    send_mail(
        subject=asunto,
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[new_email],
        fail_silently=False
    )

def resend_email(usr, new_email, otp):
    asunto = "Reenvío de código OTP"
    message = f"""
        Hola {usr.username},
        
        Tu nuevo código de verificación es: {otp}
        Este código expira en 10 minutos. 

        No lo compartas con nadie por seguridad.

        Atentamente,
        PoseCoach ❤️
        """

    send_mail(
        subject=asunto,
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[new_email],
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
        PoseCoach
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
        PoseCoach
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

def add_sms(usr, new_phone, otp):
    try:
        # Inicializar cliente Vonage
        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        sms = vonage.Sms(client)

        # Crear mensaje
        message = f"""
        Hola {usr.username},
        
        Tu codigo de verificacion es: {otp}
        Este codigo expira en 10 minutos. 

        No lo compartas con nadie por seguridad.

        Atte.
        PoseCoach
        """

        # Enviar SMS
        response = sms.send_message({
            'from': settings.VONAGE_FROM_NUMBER,
            'to': new_phone,
            'text': message
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def change_sms(usr, new_phone, otp):
    try:
        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        sms = vonage.Sms(client)

        message = f"""
        Hola {usr.username},
        
        Hemos recibido una solicitud para cambiar el numero asociado a tu cuenta.
        Tu codigo de verificacion es: {otp}
    
        Este codigo es valido por 10 minutos.
        Si no realizaste esta solicitud, ignora este mensaje.
    
        Atentamente,
        PoseCoach
        """

        sms.send_message({
            'from': settings.VONAGE_FROM_NUMBER,
            'to': new_phone,
            'text': message
        })

    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def resend_sms(usr, new_phone, otp):
    try:
        # Inicializar cliente Vonage
        client = vonage.Client(
            key=settings.VONAGE_API_KEY,
            secret=settings.VONAGE_API_SECRET
        )
        sms = vonage.Sms(client)

        # Crear mensaje
        message = f"""
        Hola {usr.username},
        
        Tu nuevo codigo de verificacion es: {otp}
        Este codigo expira en 10 minutos. 

        No lo compartas con nadie por seguridad.

        Atte.
        PoseCoach
        """

        # Enviar SMS
        response = sms.send_message({
            'from': settings.VONAGE_FROM_NUMBER,
            'to': new_phone,
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