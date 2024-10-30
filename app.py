# File: app.py
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Optional for migrations
from process_analyzer import process_analyzer
from crontab_assistant import crontab_assistant, add_cron_job, list_cron_jobs, remove_cron_job
from commands import commands  # Import the commands from commands.py
from reboot import reboot_bp  # Import the reboot Blueprint

app = Flask(__name__)

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///favorites.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Needed for flash messages

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Migrate (optional)
migrate = Migrate(app, db)

# Register the reboot Blueprint
app.register_blueprint(reboot_bp)

# Define the Favorite model
class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'command': self.command,
            'description': self.description
        }

# Register your existing routes
app.add_url_rule('/process_analyzer', view_func=process_analyzer, methods=['GET', 'POST'])
app.add_url_rule('/crontab_assistant', view_func=crontab_assistant, methods=['GET', 'POST'])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/search", methods=["POST"])
def search():
    query = request.form.get("query", "").lower()
    result = [cmd for cmd in commands if query in cmd["command"].lower() or query in cmd["description"].lower()]
    return jsonify(result)

# ----------------------------
# New Routes for Favorites
# ----------------------------

@app.route("/favorites", methods=["GET"])
def get_favorites():
    """Retrieve all favorite commands."""
    favorites = Favorite.query.all()
    return jsonify([fav.to_dict() for fav in favorites]), 200

@app.route("/favorites", methods=["POST"])
def add_favorite():
    """Add a new favorite command."""
    data = request.get_json()
    command = data.get('command')
    description = data.get('description')
    
    if not command or not description:
        return jsonify({'error': 'Both command and description are required.'}), 400

    # Create a new Favorite instance
    new_favorite = Favorite(command=command, description=description)
    
    # Add to the session and commit
    db.session.add(new_favorite)
    db.session.commit()
    
    return jsonify(new_favorite.to_dict()), 201

@app.route("/favorites/<int:favorite_id>", methods=["DELETE"])
def delete_favorite(favorite_id):
    """Delete a favorite command by ID."""
    favorite = Favorite.query.get_or_404(favorite_id)
    db.session.delete(favorite)
    db.session.commit()
    return jsonify({'message': 'Favorite deleted successfully.'}), 200

# ----------------------------
# New Route for Category-Based Filtering
# ----------------------------

@app.route("/category/<string:category_name>", methods=["GET"])
def get_commands_by_category(category_name):
    """Retrieve commands based on the specified category."""
    result = [cmd for cmd in commands if cmd["category"].lower() == category_name.lower()]
    return jsonify(result), 200

# ----------------------------

if __name__ == "__main__":
    app.run(debug=True)
