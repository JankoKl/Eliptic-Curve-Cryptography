import tkinter as tk
from tkinter import font as tkFont
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# Funkcija za generisanje ključeva
def generate_keys():
    global stanko_private_key, stanko_public_key
    stanko_private_key = ec.generate_private_key(ec.SECP256K1())
    stanko_public_key = stanko_private_key.public_key()
    keys_display.config(state=tk.NORMAL)
    keys_display.delete(1.0, tk.END)
    keys_display.insert(tk.END, "Privatni ključ:\n")
    keys_display.insert(tk.END, stanko_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode('utf-8'))
    keys_display.insert(tk.END, "\n\nJavni ključ:\n")
    keys_display.insert(tk.END, stanko_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'))
    keys_display.config(state=tk.DISABLED)
    sign_button.config(state=tk.NORMAL)  # Omogući dugme za potpisivanje nakon generisanja ključeva

# Funkcija za potpisivanje poruke
def sign_message():
    global stanko_private_key
    if stanko_private_key is None:
        status_label.config(text="Generišite ključeve pre potpisivanja.", fg="red")
        return
    message = message_entry.get().encode('utf-8')
    signature = stanko_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    signature_entry.delete(0, tk.END)
    signature_entry.insert(0, signature.hex())
    status_label.config(text="Digitalni potpis uspešno generisan.", fg="green")
    send_text_button.config(state=tk.NORMAL)  # Omogući dugme za slanje nakon potpisivanja


# Funkcija za slanje poruke
def send_text_message():
    global sent_message
    message = message_entry.get()
    sent_message = message
    conversation_text.config(state=tk.NORMAL)
    conversation_text.insert(tk.END, "\nStanko: " + message + "\n", "black")
    conversation_text.tag_config("black", foreground="black")
    conversation_text.config(state=tk.DISABLED)
    status_label.config(text="Poruka uspešno poslata Marku.", fg="green")
    verify_public_button.config(state=tk.NORMAL)  # Omogući dugme za verifikaciju javnog ključa
    send_signature_button.config(state=tk.NORMAL)

# Funkcija za slanje potpisa
def send_signature_message():
    global sent_signature
    signature = signature_entry.get()
    sent_signature = signature
    status_label.config(text="Potpis uspešno poslat Marku.", fg="green")
    verify_public_button.config(state=tk.NORMAL)  # Omogući dugme za verifikaciju javnog ključa


# Funkcija za verifikaciju javnog ključa
def verify_public_key():
    global marko_public_key
    try:
        marko_public_key = serialization.load_pem_public_key(marko_public_key_entry.get().encode('utf-8'))
        status_label.config(text="Javni ključ uspešno verifikovan.", fg="green")
        verify_signature_button.config(state=tk.NORMAL)  # Omogući dugme za verifikaciju potpisa
    except Exception as e:
        status_label.config(text="Greška pri verifikaciji javnog ključa.", fg="red")

# Funkcija za verifikaciju potpisa
def verify_signature():
    global marko_public_key
    try:
        message = sent_message.encode('utf-8')
        signature = bytes.fromhex(sent_signature)
        marko_public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        conversation_text.config(state=tk.NORMAL)
        conversation_text.insert(tk.END, "// ova poruka je verifikovana", "green")
        conversation_text.tag_config("green", foreground="green")
        conversation_text.config(state=tk.DISABLED)
        status_label.config(text="Poruka uspešno verifikovana.", fg="green")
        send_new_button.config(state=tk.NORMAL)
    except InvalidSignature:
        status_label.config(text="Verifikacija potpisa nije uspela.", fg="red")
        send_new_button.config(state=tk.NORMAL)


# Funkcija za slanje nove poruke
def send_new_message():
    global message_sent, sent_message, sent_signature
    message_entry.config(state=tk.NORMAL)
    message_entry.delete(0, tk.END)
    signature_entry.config(state=tk.NORMAL)
    signature_entry.delete(0, tk.END)
    send_text_button.config(state=tk.DISABLED)
    send_signature_button.config(state=tk.DISABLED)
    conversation_text.config(state=tk.NORMAL)
    conversation_text.delete("end-1c", "end")
    conversation_text.config(state=tk.DISABLED)
    status_label.config(text="Unesite novu poruku i potpišite je.")
    message_sent = False
    sent_message = None
    sent_signature = None
    verify_public_button.config(state=tk.DISABLED)
    verify_signature_button.config(state=tk.DISABLED)
    send_new_button.config(state=tk.DISABLED)



# Kreiranje glavnog prozora
root = tk.Tk()
root.title("Demo Kriptografija Eliptične Krive")
root.attributes("-fullscreen", True)



# Postupak za izlazak iz fullscreen moda (Escape dugme)
def exit_fullscreen(event):
    root.attributes("-fullscreen", False)
    exit_button.destroy()  # Ukloni dugme za izlazak

root.bind("<Escape>", exit_fullscreen)


# Polje za unos poruke
message_label = tk.Label(root, text="Unesite poruku:")
message_label.pack()

message_entry = tk.Entry(root, width=50)
message_entry.pack()

# Dugme za generisanje ključeva
generate_keys_button = tk.Button(root, text="Generiši ključeve", command=generate_keys)
generate_keys_button.pack()

# Polje za prikaz generisanih ključeva
keys_display = tk.Text(root, height=10, width=60, state=tk.DISABLED)
keys_display.pack()

# Dugme za potpisivanje poruke
sign_button = tk.Button(root, text="Potpiši poruku", command=sign_message, state=tk.DISABLED)  # Početno onemogućeno
sign_button.pack()

# Polje za unos potpisa
signature_label = tk.Label(root, text="Unesite potpis:")
signature_label.pack()

signature_entry = tk.Entry(root, width=50)
signature_entry.pack()

# Dugme za slanje teksta
send_text_button = tk.Button(root, text="Pošalji tekstualnu poruku", command=send_text_message, state=tk.DISABLED)
send_text_button.pack()

# Dugme za slanje digitalnog potpisa
send_signature_button = tk.Button(root, text="Pošalji potpis poruke", command=send_signature_message, state=tk.DISABLED)
send_signature_button.pack()

# Tekstualno polje za prikaz razgovora
conversation_text = tk.Text(root, height=10, width=60, state=tk.DISABLED)
conversation_text.pack()

# Statusno polje
status_label = tk.Label(root, text="", fg="green")
status_label.pack()

# Polje za unos Markovog javnog ključa
marko_public_key_label = tk.Label(root, text="Unesite Markov javni ključ:")
marko_public_key_label.pack()

marko_public_key_entry = tk.Entry(root, width=50)
marko_public_key_entry.pack()

# Dugme za verifikaciju javnog ključa
verify_public_button = tk.Button(root, text="Verifikuj javni ključ", command=verify_public_key, state=tk.DISABLED)  # Početno onemogućeno
verify_public_button.pack()

# Dugme za verifikaciju potpisa
verify_signature_button = tk.Button(root, text="Verifikuj potpis", command=verify_signature, state=tk.DISABLED)  # Početno onemogućeno
verify_signature_button.pack()

# Dugme za izlazak iz aplikacije
font_style = tkFont.Font(family="Helvetica", size=16, weight="bold")
exit_button = tk.Button(root, text="Izađi", command=root.quit, width=6, height=3, bg="red", fg="white", font=font_style)
exit_button.place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)


stanko_private_key = None
stanko_public_key = None
sent_message = None
sent_signature = None
marko_public_key = None
message_sent = False


# Dugme za slanje nove poruke
send_new_button = tk.Button(root, text="Pošalji novu poruku", command=send_new_message, state=tk.DISABLED)
send_new_button.pack()

root.mainloop()
