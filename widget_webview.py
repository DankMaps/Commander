# File: flask_widget_tkinter_webview.py

import threading
import webview
import requests
from tkinter import Tk
from ttkbootstrap import Style
from ttkbootstrap.widgets import Button, Entry, Label, Frame
from subprocess import Popen

def run_flask_app():
    Popen(['python', 'app.py'])

def search_commands(query):
    # Send the query to the Flask app's search API
    try:
        response = requests.post("http://localhost:5000/search", data={"query": query})
        response.raise_for_status()
        results = response.json()
        return results

    except requests.exceptions.RequestException as e:
        return [{"command": "Error", "description": str(e)}]

def create_html_page(commands):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Command Search Results</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f4f4f4;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            th, td {
                padding: 12px;
                border: 1px solid #ddd;
                text-align: left;
            }
            th {
                background-color: #007bff;
                color: white;
            }
            td a {
                color: #007bff;
                text-decoration: none;
                cursor: pointer;
            }
            td a:hover {
                text-decoration: underline;
            }
        </style>
        <script>
            function copyToClipboard(command) {
                navigator.clipboard.writeText(command).then(() => {
                    alert("Copied: " + command);
                });
            }
        </script>
    </head>
    <body>
        <h1>Search Results</h1>
        <table>
            <tr>
                <th>Command</th>
                <th>Description</th>
            </tr>
    """

    for cmd in commands:
        html_content += f"""
            <tr>
                <td><a onclick="copyToClipboard('{cmd['command']}')">{cmd['command']}</a></td>
                <td>{cmd['description']}</td>
            </tr>
        """

    html_content += """
            </table>
        </body>
    </html>
    """
    return html_content

def display_results(commands):
    html_content = create_html_page(commands)
    webview.create_window('Command Search Results', html=html_content, width=600, height=400)  # Set default size
    webview.start()

def search_commands_and_display():
    query = search_entry.get()
    results = search_commands(query)
    display_results(results)

# Create the Tkinter window with ttkbootstrap styling
style = Style(theme="superhero")
root = style.master
root.title("Flask Command Search")
root.geometry("600x200")

# Frame for containing widgets
frame = Frame(root)
frame.pack(pady=20, padx=20)

# Label for search
search_label = Label(frame, text="Enter a command or keyword:", font=("Helvetica", 14))
search_label.pack(pady=5)

# Entry widget for command search
search_entry = Entry(frame, font=("Helvetica", 12), width=50)
search_entry.pack(pady=5)

# Search button to trigger command search
search_button = Button(frame, text="Search Commands", bootstyle="primary", command=search_commands_and_display)
search_button.pack(pady=10)

# Run Flask app in a separate thread
flask_thread = threading.Thread(target=run_flask_app)
flask_thread.start()

# Run the Tkinter event loop
root.mainloop()
