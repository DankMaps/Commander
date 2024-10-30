# File: reboot.py
from flask import Blueprint, render_template

# Create a Blueprint for reboot functionality
reboot_bp = Blueprint('reboot', __name__)

@reboot_bp.route('/reboot', methods=['GET'])
def reboot_guide():
    """
    Render the reboot guide page with step-by-step instructions.
    """
    return render_template('reboot.html')
