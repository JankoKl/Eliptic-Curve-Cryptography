import tkinter as tk
from tkinter import font as tkFont, Scrollbar
from cryptography.hazmat.primitives import serialization


class ECC_UIElements:
    def __init__(self, app):
        self.app = app

    def initialize_ui(self):
        root = self.app.root
        root.title("ECC Messaging Demo")
        root.attributes("-fullscreen", True)
        root.bind("<Escape>", self.exit_fullscreen)

        # Message input
        self.message_label = tk.Label(root, text="Enter message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack()

        # Generate Keys Button
        self.generate_keys_button = tk.Button(root, text="Generate Keys", command=self.app.generate_keys)
        self.generate_keys_button.pack()

        # Keys display
        self.keys_frame = tk.Frame(root)
        self.keys_frame.pack()

        self.keys_display = tk.Text(self.keys_frame, height=10, width=60, state=tk.DISABLED)
        self.keys_scrollbar = Scrollbar(self.keys_frame, command=self.keys_display.yview)
        self.keys_display.config(yscrollcommand=self.keys_scrollbar.set)
        self.keys_display.pack(side=tk.LEFT, fill=tk.BOTH)
        self.keys_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Sign Message Button
        self.sign_button = tk.Button(root, text="Sign Message", command=self.app.sign_message, state=tk.DISABLED)
        self.sign_button.pack()

        # Display Signature
        self.signature_label = tk.Label(root, text="Generated Signature:")
        self.signature_label.pack()

        self.signature_entry = tk.Entry(root, width=50)
        self.signature_entry.pack()

        # Send Message Button
        self.send_text_button = tk.Button(root, text="Send Message", command=self.app.send_text_message, state=tk.DISABLED)
        self.send_text_button.pack()

        # Conversation Display
        self.conversation_text = tk.Text(root, height=10, width=60, state=tk.DISABLED)
        self.conversation_text.pack()

        # Status Label
        self.status_label = tk.Label(root, text="", fg="green")
        self.status_label.pack()

        # Marko's Public Key input
        self.marko_public_key_label = tk.Label(root, text="Enter Marko's Public Key:")
        self.marko_public_key_label.pack()

        self.marko_public_key_entry = tk.Entry(root, width=50)
        self.marko_public_key_entry.pack()

        # Verify Public Key Button
        self.verify_public_button = tk.Button(root, text="Verify Public Key", command=self.app.verify_public_key, state=tk.DISABLED)
        self.verify_public_button.pack()

        # Verify Signature Button
        self.verify_signature_button = tk.Button(root, text="Verify Signature", command=self.app.verify_signature, state=tk.DISABLED)
        self.verify_signature_button.pack()

        # Send Another Message Button
        self.new_message_button = tk.Button(root, text="Send Another Message", command=self.app.prepare_for_new_message, state=tk.DISABLED)
        self.new_message_button.pack()

        # Start New Conversation Button
        self.new_conversation_button = tk.Button(root, text="Start New Conversation", command=self.app.reset_application)
        self.new_conversation_button.pack()

        # Exit Button
        font_style = tkFont.Font(family="Helvetica", size=16, weight="bold")
        self.exit_button = tk.Button(root, text="Exit", command=root.quit, width=6, height=3, bg="red", fg="white", font=font_style)
        self.exit_button.place(relx=1.0, rely=0.0, anchor='ne', x=-10, y=10)

    # Method to exit fullscreen
    def exit_fullscreen(self, event=None):
        self.app.root.attributes("-fullscreen", False)

    # Method to update the displayed keys
    def update_keys_display(self, public_key, private_key):
        self.keys_display.config(state=tk.NORMAL)
        self.keys_display.delete(1.0, tk.END)
    
        self.keys_display.insert(tk.END, "Public Key:\n")
        self.keys_display.insert(tk.END, public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8'))
    
    # Only show that private key exists, not the actual key
        self.keys_display.insert(tk.END, "\n\nPrivate Key: [GENERATED - HIDDEN]")
        self.keys_display.config(state=tk.DISABLED)

    # Method to display the generated signature
    def display_signature(self, signature):
        self.signature_entry.delete(0, tk.END)
        self.signature_entry.insert(0, signature)

    # Method to display messages in conversation
    def display_message_in_conversation(self, message, color):
        self.conversation_text.config(state=tk.NORMAL)
        self.conversation_text.insert(tk.END, f"{message}\n", color)
        self.conversation_text.tag_config(color, foreground=color)
        self.conversation_text.config(state=tk.DISABLED)

    # Get Marko's public key from entry field
    def get_marko_public_key(self):
        return self.marko_public_key_entry.get()

    # Method to update status messages
    def update_status(self, message, color):
        self.status_label.config(text=message, fg=color)

    # Methods to enable or disable buttons depending on app state
    def enable_send_button(self):
        self.send_text_button.config(state=tk.NORMAL)

    def enable_public_key_verification(self):
        self.verify_public_button.config(state=tk.NORMAL)

    def enable_signature_verification(self):
        self.verify_signature_button.config(state=tk.NORMAL)

    # Reset UI components for a new set of keys
    def reset_for_new_keys(self):
        self.signature_entry.delete(0, tk.END)
        self.marko_public_key_entry.delete(0, tk.END)
        self.update_status("New keys generated. Ready to sign new messages.", "green")
        self.sign_button.config(state=tk.NORMAL)
        self.send_text_button.config(state=tk.DISABLED)
        self.verify_public_button.config(state=tk.DISABLED)
        self.verify_signature_button.config(state=tk.DISABLED)
        self.new_message_button.config(state=tk.DISABLED)

    # Method to clear the message entry field
    def clear_message_entry(self):
        self.message_entry.delete(0, tk.END)

    # Prepare UI for sending a new message
    def prepare_for_new_message(self):
        self.clear_message_entry()
        self.signature_entry.delete(0, tk.END)
        self.update_status("Ready to send another message.", "green")
        self.sign_button.config(state=tk.NORMAL)
        self.send_text_button.config(state=tk.DISABLED)
        self.verify_signature_button.config(state=tk.DISABLED)

    def prepare_for_verified_state(self):

        # Disable buttons related to signing, sending, and verification, as the current message has been verified
        self.sign_button.config(state=tk.DISABLED)
        self.send_text_button.config(state=tk.DISABLED)
        self.verify_public_button.config(state=tk.DISABLED)
        self.verify_signature_button.config(state=tk.DISABLED)

        # Enable the buttons for sending a new message or starting a new conversation
        self.new_message_button.config(state=tk.NORMAL)
        self.new_conversation_button.config(state=tk.NORMAL)

    # Reset the entire UI
    def reset_ui(self):
        self.message_entry.delete(0, tk.END)
        self.signature_entry.delete(0, tk.END)
        self.keys_display.config(state=tk.NORMAL)
        self.keys_display.delete(1.0, tk.END)
        self.keys_display.config(state=tk.DISABLED)
        self.conversation_text.config(state=tk.NORMAL)
        self.conversation_text.delete(1.0, tk.END)
        self.conversation_text.config(state=tk.DISABLED)
        self.marko_public_key_entry.delete(0, tk.END)
        self.update_status("", "green")
        self.sign_button.config(state=tk.DISABLED)
        self.send_text_button.config(state=tk.DISABLED)
        self.verify_public_button.config(state=tk.DISABLED)
        self.verify_signature_button.config(state=tk.DISABLED)
        self.new_message_button.config(state=tk.DISABLED)
