# File: create_db.py
from app import db

# Create all tables
db.create_all()
print("Database and tables created.")
