import string
import requests
import random
from django.conf import settings
def send_otp_to_phone(phone_number):
    try:
        otp=str(random.randint(100000,999999))
        url = f"https://2factor.in/API/V1/{settings.API_KEY}/SMS/+91{phone_number}/{otp}"
        response=requests.get(url)
        return otp
    except Exception as e:
      return None
    


def random_password(length=8):
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    special_characters = '!@#$%^&*()_+-=[]{};\:|,.<>/?'
    
    # Ensure the password meets the required criteria
    password = random.choice(uppercase_letters)
    password += random.choice(lowercase_letters)
    password += random.choice(digits)
    password += random.choice(special_characters)
    
    # Generate the remaining characters
    remaining_characters = length - 4
    characters = uppercase_letters + lowercase_letters + digits + special_characters
    password += ''.join(random.choice(characters) for _ in range(remaining_characters))
    
    # Shuffle the password
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)
    
    return password    



def generate_password(length=8):
    characters = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{};\:|,.<>/?'
    return ''.join(random.choice(characters) for _ in range(length))