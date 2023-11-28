from tkinter import Tk, Text, BOTH, W, N, E, S
from tkinter.ttk import Frame, Button, Label, Style
from tkinter import *
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes

from Import_Function import encrypt_text_AES, decrypt_text_AES

key = os.urandom(16)
(publickey, privatekey) = rsa.newkeys(512)
key_1 = get_random_bytes(16)
# Генерация ключевой пары DSA
private_key_DS = dsa.generate_private_key(key_size=1024)
public_key_DS = private_key_DS.public_key()

class Example(Frame):

    def __init__(self):
        super().__init__()
        self.original_text = ""
        self.active_algorithm = None
        self.initUI()
    
 
    def initUI(self):
        def encrypt_text_RSA(message):
            enc_message = message
            crypto = rsa.encrypt(enc_message,publickey)
            show_message_shifrhex(crypto.hex())
            

        def decrypt_text_RSA(message):
            dec_message = bytes.fromhex(message)
            crypto = rsa.decrypt(dec_message, privatekey)
            show_message_decrypted(str(crypto.decode('utf-8')))

 
        def algo_DS(message):
            self.original_text = message

            # Создание цифровой подписи
            signature = private_key_DS.sign(message, hashes.SHA256())
            show_message_shifrhex(signature.hex())
        
        def verify_signature(message):
             verification_digest = bytes.fromhex(message)
             # Проверка цифровой подписи
             try:
                public_key_DS.verify(verification_digest, self.original_text, hashes.SHA256())
                result.delete('1.0', END)
                result.insert('1.0', "Цифровая подпись верна")
                 
             except:
                result.delete('1.0', END)
                result.insert('1.0', "Цифровая подпись неверна")
                

        def encrypt_algorithm(index_algorithm):
            self.active_algorithm = index_algorithm

            if index_algorithm == 1:
                plaintext = area.get("1.0", END).strip()
                ciphertext = encrypt_text_AES(plaintext)
                show_message_shifrhex(ciphertext.hex())
            elif index_algorithm == 2:
                plaintext = area.get("1.0", END).strip().encode()
                encrypt_text_RSA(plaintext)
            else:
                plaintext = area.get("1.0", END).strip().encode()
                algo_DS(plaintext)

            obtn.config(state="disable" if self.active_algorithm == None else "normal")
            setAlgorithmActive()
          

        def decrypt_algorithm():
            if  self.active_algorithm == 1:
                plaintext = area.get("1.0", END).strip()
                decrypted_message = decrypt_text_AES(plaintext)
                show_message_decrypted(decrypted_message)
            elif self.active_algorithm == 2:
                plaintext = area.get("1.0", END).strip()
                decrypt_text_RSA(plaintext)
            else:  
                plaintext = area.get("1.0", END).strip()
                verify_signature(plaintext)

        def show_message_shifrhex(ciphertext):
            result.delete('1.0', END)
            result.insert('1.0', ciphertext)

        def show_message_decrypted(decrypted_text):
            result.delete('1.0', END)
            result.insert('1.0', decrypted_text)
 
        def setAlgorithmActive():
            abtn.config(state="active" if self.active_algorithm == 1 else "normal")
            cbtn.config(state="active" if self.active_algorithm == 2 else "normal")
            lbtn.config(state="active" if self.active_algorithm == 3 else "normal")
        
        def copy_to_clipboard(event):
            # Get the selected text from the Text widget
            selected_text = event.widget.selection_get()

            # Put the selected text into the clipboard
            event.widget.clipboard_clear()
            event.widget.clipboard_append(selected_text)
            pass

        def paste_from_clipboard(event):
            # Get the text from the clipboard
            text = event.widget.clipboard_get()


        self.master.title("Диалоговое окно")
        self.pack(fill=BOTH, expand=True)
 
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(3, pad=7)

        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self.grid_rowconfigure(5, weight=1)
        self.grid_rowconfigure(6, pad=7)

        abtn = Button(self, command=lambda:encrypt_algorithm(1), text="Алгоритм AES", font=('Calibri', 12, 'italic'), bg='green', relief='flat', background="#FFD4D4", activebackground="#fcd5ce", foreground="#111", activeforeground="#0077b6", borderwidth=2)
        cbtn = Button(self, command=lambda:encrypt_algorithm(2),text="Алгоритм RSA", font=('Calibri', 12, 'italic'), bg='green', relief='flat', background="#FFD4D4", activebackground="#fcd5ce", foreground="#111", activeforeground="#0077b6", borderwidth=2)
        lbtn = Button(self, command=lambda:encrypt_algorithm(3),text="Цифр. подпись", font=('Calibri', 12, 'italic'), bg='green', relief='flat', background="#FFD4D4", activebackground="#fcd5ce", foreground="#111", activeforeground="#0077b6", borderwidth=2)

        abtn.grid(row=0, column=0, padx=5, pady=10)
        cbtn.grid(row=0, column=1, padx=5, pady=10)
        lbtn.grid(row=0, column=2, padx=5, pady=10)

        area = Text(self)
        area.configure(background="#F5F5F5", font=("Calibri", 12))
        area.grid(row=2, column=0, columnspan=4, rowspan=2, padx=5)

        area.bind("<Control-c>", copy_to_clipboard)
        area.bind("<Control-v>", paste_from_clipboard)
        
      #  area.event_generate('<<Paste>>')

        result = Text(self)
        result.configure(background="#F5F5F5", font=("Calibri", 12))
        result.grid(row=4, column=0, columnspan=4, rowspan=2, padx=5)

        result.bind("<Control-c>", copy_to_clipboard)

        obtn = Button(
            self, 
            command=lambda:decrypt_algorithm(), 
            text="Расшифровать", font=('Calibri', 12, 'italic'), 
            bg='green', 
            relief='flat', 
            background="#FFD4D4", 
            activebackground="#fcd5ce", 
            foreground="#111", 
            activeforeground="#0077b6", 
            borderwidth=2,
            state="disabled"
        )

        obtn.grid(row=6, column=3, padx=5, pady=10)
 
def main():
 
    root = Tk()
    root.geometry("800x600")
    app = Example()
    app.configure(background="#9898F5")
    root.mainloop()
 
 
if __name__ == '__main__':
    main()
