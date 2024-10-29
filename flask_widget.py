# File: flask_widget.py

import sys
import threading
import requests
from PyQt5.QtWidgets import QApplication, QPushButton, QVBoxLayout, QWidget, QLineEdit, QTextEdit, QLabel
from subprocess import Popen

# Function to run the Flask app in a separate thread
def run_flask_app():
    Popen(['python', 'app.py'])

# PyQt5 interface with a search input to query Flask commands
class FlaskAppWidget(QWidget):
    def __init__(self):
        super().__init__()

        # Set up the layout
        layout = QVBoxLayout()

        # Add label
        self.label = QLabel("Enter a command or keyword:")
        layout.addWidget(self.label)

        # Search input
        self.query_input = QLineEdit(self)
        layout.addWidget(self.query_input)

        # Search button
        self.search_button = QPushButton("Search Commands")
        self.search_button.clicked.connect(self.search_commands)
        layout.addWidget(self.search_button)

        # Text area to display results
        self.result_area = QTextEdit(self)
        self.result_area.setReadOnly(True)
        layout.addWidget(self.result_area)

        self.setLayout(layout)
        self.setWindowTitle("Flask Command Search")
        self.setGeometry(300, 300, 400, 300)

    # Method to send query to the Flask app and display results
    def search_commands(self):
        query = self.query_input.text()

        # Send the query to the Flask app
        try:
            response = requests.post("http://localhost:5000/search", data={"query": query})
            response.raise_for_status()
            results = response.json()

            # Display results in the text area
            if results:
                result_text = "\n".join([f"{cmd['command']}: {cmd['description']}" for cmd in results])
            else:
                result_text = "No matching commands found."
            self.result_area.setPlainText(result_text)

        except requests.exceptions.RequestException as e:
            self.result_area.setPlainText(f"Error: {e}")

# Main function to start the Flask app in a thread and display the PyQt window
def main():
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    # Create the PyQt application
    app = QApplication(sys.argv)
    flask_widget = FlaskAppWidget()
    flask_widget.show()

    # Start the PyQt event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
