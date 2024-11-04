import tkinter as tk
from tkinter import font as tkFont, Scrollbar
from key_manager import KeyManager
from message_manager import MessageManager
from ui import ECC_UIElements


class ECC_Demo:
    def __init__(self, root):
        self.root = root
        self.key_manager = KeyManager()
        self.message_manager = MessageManager(self.key_manager)
        self.ui = ECC_UIElements(self)

        self.sent_messages = []
        self.sent_signatures = []

        self.ui.initialize_ui()

    def generate_keys(self):
        self.key_manager.generate_keys()

        # Update UI with new keys
        self.ui.update_keys_display(self.key_manager.stanko_public_key, self.key_manager.stanko_private_key)
        self.ui.reset_for_new_keys()

    def sign_message(self):
        message = self.ui.message_entry.get()
        if not message:
            self.ui.update_status("Message cannot be empty.", "red")
            return

        signature = self.message_manager.sign_message(message)
        if signature:
            self.sent_messages.append(message)
            self.sent_signatures.append(signature)
            self.ui.display_signature(signature)
            self.ui.update_status("Digital signature generated.", "green")
            self.ui.enable_send_button()

    def send_text_message(self):
        message = self.ui.message_entry.get()
        self.ui.display_message_in_conversation(f"Stanko: {message}", "black")
        self.ui.clear_message_entry()
        self.ui.update_status("Message sent to Marko.", "green")
        self.ui.enable_public_key_verification()

    def verify_public_key(self):
        marko_key = self.ui.get_marko_public_key()
        if self.key_manager.verify_public_key(marko_key):
            self.ui.update_status("Public key verified successfully.", "green")
            self.ui.enable_signature_verification()
        else:
            self.ui.update_status("Error verifying public key.", "red")

    def verify_signature(self):
        if not self.sent_messages or not self.sent_signatures:
            self.ui.update_status("No message or signature to verify.", "red")
            return

        message = self.sent_messages[-1]
        signature = self.sent_signatures[-1]

        if self.message_manager.verify_signature(message, signature):
            self.ui.display_message_in_conversation("// Message verified", "green")
            self.ui.update_status("Message verified successfully.", "green")
            self.ui.prepare_for_verified_state()
        else:
            self.ui.update_status("Signature verification failed.", "red")

    def prepare_for_new_message(self):
        self.ui.prepare_for_new_message()

    def reset_application(self):
        self.sent_messages.clear()
        self.sent_signatures.clear()
        self.key_manager.reset_keys()
        self.ui.reset_ui()


root = tk.Tk()
app = ECC_Demo(root)
root.mainloop()
