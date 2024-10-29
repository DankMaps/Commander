from flask import Flask, render_template, request, redirect, url_for
import psutil  # New import for process information
import subprocess  # New import for running system commands
import re
from crontab import CronTab  # Import CronTab for crontab assistant

app = Flask(__name__)

@app.route('/process_analyzer', methods=['GET', 'POST'])
def process_analyzer():
    analysis = None
    if request.method == 'POST':
        command_type = request.form['command_type']
        # For ps command, we no longer need user input
        if command_type == 'ps':
            analysis = analyze_ps_output()
        elif command_type == 'systemctl':
            analysis = analyze_systemctl_output()
        elif command_type == 'service':
            analysis = analyze_service_output()
        elif command_type == 'logfile':  # New log file analyzer
            log_content = request.form['log_content']
            analysis = analyze_log_file(log_content)
    return render_template('process_analyzer.html', analysis=analysis)

# Existing analysis functions remain the same...

def analyze_ps_output():
    # ... existing code remains unchanged ...
    pass  # Replace with your existing code

def analyze_systemctl_output():
    # ... existing code remains unchanged ...
    pass  # Replace with your existing code

def analyze_service_output():
    # ... existing code remains unchanged ...
    pass  # Replace with your existing code

def analyze_log_file(log_content):
    # ... existing code remains unchanged ...
    pass  # Replace with your existing code

# Crontab Assistant Functions

@app.route('/crontab_assistant', methods=['GET', 'POST'])
def crontab_assistant():
    message = None
    crontab_text = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            command = request.form.get('command')
            schedule = request.form.get('schedule', '* * * * *')
            if command:
                add_cron_job(command, schedule)
                message = f"Cron job added: {command} with schedule '{schedule}'"
                crontab_text = get_crontab_text()  # Get the crontab text to display
            else:
                message = "Please provide a command to schedule."
        elif action == 'remove':
            command = request.form.get('command')
            if command:
                remove_cron_job(command)
                message = f"Removed cron jobs matching command: {command}"
                crontab_text = get_crontab_text()  # Get the updated crontab text to display
            else:
                message = "Please provide a command to remove."
    cron_jobs = list_cron_jobs()
    return render_template('crontab_assistant.html', cron_jobs=cron_jobs, message=message, crontab_text=crontab_text)

def add_cron_job(command, schedule='* * * * *', user=True):
    """Add a new cron job."""
    cron = CronTab(user=user)
    job = cron.new(command=command)
    job.setall(schedule)
    cron.write()

def list_cron_jobs(user=True):
    """List all cron jobs."""
    cron = CronTab(user=user)
    return list(cron)

def remove_cron_job(command, user=True):
    """Remove cron jobs matching the command."""
    cron = CronTab(user=user)
    cron.remove_all(command=command)
    cron.write()

def get_crontab_text(user=True):
    """Get the current crontab as text."""
    cron = CronTab(user=user)
    return cron.render()  # Return the crontab content as text

if __name__ == '__main__':
    app.run(debug=True)
