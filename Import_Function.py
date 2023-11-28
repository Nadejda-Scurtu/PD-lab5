from tkinter import Tk, Text, BOTH, W, N, E, S
from tkinter.ttk import Frame, Button, Label, Style
from tkinter import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
key_1 = get_random_bytes(16)

def encrypt_text_AES(message):
  """
  Encrypts the input text using AES encryption in ECB mode.

  Parameters:
  message (str): The text to be encrypted.

  Returns:
  None: Displays the hexadecimal representation of the ciphertext.

  Usage:
  encrypt_text_AES("Hello, World!")
  """
  # Инициализируем AES с использованием ключа и режима шифрования ECB
  cipher = AES.new(key_1, AES.MODE_ECB)

  # Приводим сообщение к длине, кратной 16 байтам
  while len(message) % 16 != 0:
      message += ' '

  # Зашифровываем сообщение
  ciphertext = cipher.encrypt(message.encode('utf-8'))
  return ciphertext
       
def decrypt_text_AES(ciphertext):
  """
  Decrypts the input ciphertext using AES decryption in ECB mode.

  Parameters:
  ciphertext (str): The hexadecimal representation of the ciphertext to be decrypted.

  Returns:
  None: Displays the decrypted text.

  Usage:
  decrypt_text_AES("2df8a3b46a77c8a4d92f...")
  """
  # Инициализируем AES с использованием ключа и режима шифрования ECB
  cipher = AES.new(key_1, AES.MODE_ECB)
  
  # Расшифровываем сообщение
  decrypted_message = cipher.decrypt(bytes.fromhex(ciphertext))
  decrypted_message.decode('utf-8')
        
  return decrypted_message
