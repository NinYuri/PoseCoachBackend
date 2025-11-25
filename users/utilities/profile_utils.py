from django.core.cache import cache

def save_temp_change(user_id, email=None, phone=None, otp=None, otp_time=None):
    cache.set(
        f"profile_change_{user_id}",
        {
            "email": email,
            "phone": phone,
            "otp": otp,
            "otp_time": otp_time,
        },
        timeout=10 * 60
    )

def get_temp_change(user_id):
    return cache.get(f"profile_change_{user_id}")

def clear_temp_change(user_id):
    cache.delete(f"profile_change_{user_id}")