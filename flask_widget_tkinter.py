# File: flask_widget_tkinter_bootstrap.py

import threading
import requests
from tkinter import Text, Scrollbar, END, Tk
from ttkbootstrap import Style  # Import ttkbootstrap for modern styling
from ttkbootstrap.widgets import Button, Entry, Label, Frame  # Use ttkbootstrap widgets
from subprocess import Popen

def run_flask_app():
    # Start Flask app in a separate process
    Popen(['python', 'app.py'])

def search_commands(event=None):  # Allow event for Enter key
    # Get the search query from the input field
    query = search_entry.get()

    # Send the query to the Flask app's search API
    try:
        response = requests.post("http://localhost:5000/search", data={"query": query})
        response.raise_for_status()
        results = response.json()

        # Clear the text widget before displaying new results
        result_text.delete(1.0, END)

        # Display the commands in a formatted table
        if results:
            # Header
            result_text.insert(END, f"{'Command':<40} {'Description'}\n")
            result_text.insert(END, "-" * 80 + "\n")  # Separator
            for cmd in results:
                command_display = f"{cmd['command']:<40}"  # Align command to the left
                result_text.insert(END, f"{command_display} {cmd['description']}\n")
        else:
            result_text.insert(END, "No matching commands found.\n")

    except requests.exceptions.RequestException as e:
        result_text.insert(END, f"Error: {e}\n")

def copy_to_clipboard(command):
    # Copy the command to the clipboard
    root.clipboard_clear()
    root.clipboard_append(command)
    result_text.insert(END, f"Copied: {command}\n")

# Create the Tkinter window with ttkbootstrap styling
style = Style(theme="superhero")  # You can change the theme here to other available themes
root = style.master
root.title("Flask Command Search")
root.geometry("600x450")  # Increased width for better layout

# Frame for containing widgets
frame = Frame(root)
frame.pack(pady=20, padx=20)

# Label for search
search_label = Label(frame, text="Enter a command or keyword:", font=("Helvetica", 14), bootstyle="info")  # Modern font and style
search_label.pack(pady=5)

# Entry widget for command search
search_entry = Entry(frame, font=("Helvetica", 12), width=60)
search_entry.pack(pady=5)
search_entry.bind("<Return>", search_commands)  # Bind Enter key to search

# Search button to trigger command search
search_button = Button(frame, text="Search Commands", bootstyle="primary", command=search_commands)
search_button.pack(pady=10)

# Text widget to display the search results
result_text = Text(frame, height=15, width=70, wrap="word", font=("Courier New", 11), background="#F9F9F9", foreground="#333333", borderwidth=1, relief="flat")
result_text.pack(pady=10)

# Scrollbar for the text widget
scrollbar = Scrollbar(frame)
scrollbar.pack(side="right", fill="y")
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=result_text.yview)

# Run Flask app in a separate thread
flask_thread = threading.Thread(target=run_flask_app)
flask_thread.start()

# Run the Tkinter event loop
root.mainloop()
