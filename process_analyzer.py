from flask import Flask, render_template, request
import psutil  # New import for process information
import subprocess  # New import for running system commands
import re

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

# Existing PS, systemctl, and service analysis code remains the same

def analyze_ps_output():
    try:
        # Here, you would use subprocess to run the ps aux command and capture its output
        result = subprocess.run(['ps', 'aux', '--no-heading'], stdout=subprocess.PIPE, text=True)
        output = result.stdout

        # Split the output into lines
        lines = output.strip().split('\n')
        if len(lines) < 1:
            return 'Invalid ps output.'

        processes = []

        # Iterate over each line and extract process details
        for line in lines:
            parts = re.split(r'\s+', line, maxsplit=10)  # Split by whitespace with a limit of 10 parts (command might have spaces)

            if len(parts) < 11:
                continue  # Skip lines that don't have the expected number of columns

            # Extract the process information
            process_info = {
                'USER': parts[0],
                'PID': int(parts[1]),
                '%CPU': float(parts[2]),
                '%MEM': float(parts[3]),
                'VSZ': parts[4],  # Virtual memory size
                'RSS': parts[5],  # Resident Set Size
                'TTY': parts[6],  # TTY
                'STAT': parts[7],  # Process state
                'START': parts[8],  # Start time
                'TIME': parts[9],  # CPU time
                'COMMAND': parts[10]  # Command with arguments
            }

            processes.append(process_info)

        # Identify high CPU usage processes
        high_cpu_threshold = 10.0  # Adjust as needed
        high_cpu_processes = [p for p in processes if p['%CPU'] > high_cpu_threshold]

        # Identify high memory usage processes
        high_mem_threshold = 10.0  # Adjust as needed
        high_mem_processes = [p for p in processes if p['%MEM'] > high_mem_threshold]

        # Identify zombie processes
        zombie_processes = [p for p in processes if 'Z' in p['STAT']]

        # Identify processes run by root
        root_processes = [p for p in processes if p['USER'] == 'root']

        # Build the analysis report
        analysis = '<h3>Analysis of ps Output:</h3>'

        if high_cpu_processes:
            analysis += '<p><strong>High CPU Usage Processes:</strong></p><ul>'
            for p in high_cpu_processes:
                analysis += f"<li>PID {p['PID']} ({p['COMMAND']}): {p['%CPU']}% CPU</li>"
            analysis += '</ul>'
        else:
            analysis += '<p>No processes with high CPU usage detected.</p>'

        if high_mem_processes:
            analysis += '<p><strong>High Memory Usage Processes:</strong></p><ul>'
            for p in high_mem_processes:
                analysis += f"<li>PID {p['PID']} ({p['COMMAND']}): {p['%MEM']}% Memory</li>"
            analysis += '</ul>'
        else:
            analysis += '<p>No processes with high memory usage detected.</p>'

        if zombie_processes:
            analysis += '<p><strong>Zombie Processes Detected:</strong></p><ul>'
            for p in zombie_processes:
                analysis += f"<li>PID {p['PID']} ({p['COMMAND']})</li>"
            analysis += '</ul>'
        else:
            analysis += '<p>No zombie processes detected.</p>'

        if root_processes:
            analysis += '<p><strong>Processes Running as root:</strong></p><ul>'
            for p in root_processes:
                analysis += f"<li>PID {p['PID']} ({p['COMMAND']})</li>"
            analysis += '</ul>'

        return analysis

    except Exception as e:
        return f'An error occurred while analyzing ps output: {str(e)}'

def analyze_systemctl_output():
    try:
        # Execute the systemctl command
        result = subprocess.run(['systemctl', 'list-units', '--all', '--type=service', '--no-pager', '--no-legend'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        if result.stderr:
            return f'Error executing systemctl command: {result.stderr}'

        lines = output.strip().split('\n')
        if not lines:
            return 'No services found.'

        failed_services = []
        inactive_services = []
        for line in lines:
            # Split the line into columns
            columns = line.split(None, 4)
            if len(columns) >= 5:
                unit = columns[0]
                load = columns[1]
                active = columns[2]
                sub = columns[3]
                description = columns[4]
                if active.lower() == 'failed':
                    failed_services.append(unit)
                elif active.lower() == 'inactive':
                    inactive_services.append(unit)

        analysis = '<h3>Analysis of Systemctl Services:</h3>'

        if failed_services:
            analysis += '<p><strong>Failed Services:</strong></p><ul>'
            for service in failed_services:
                analysis += f'<li>{service}</li>'
            analysis += '</ul>'
        else:
            analysis += '<p>No failed services detected.</p>'

        if inactive_services:
            analysis += '<p><strong>Inactive Services:</strong></p><ul>'
            for service in inactive_services:
                analysis += f'<li>{service}</li>'
            analysis += '</ul>'
        else:
            analysis += '<p>No inactive services detected.</p>'

        return analysis

    except Exception as e:
        return f'An error occurred while analyzing systemctl output: {str(e)}'

def analyze_service_output():
    try:
        # Execute the service command
        result = subprocess.run(['service', '--status-all'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        if result.stderr:
            return f'Error executing service command: {result.stderr}'

        lines = output.strip().split('\n')
        if not lines:
            return 'No services found.'

        running_services = []
        stopped_services = []
        unknown_services = []

        for line in lines:
            match = re.match(r'\s*\[\s*([+-?])\s*\]\s+(.*)', line)
            if match:
                status_symbol, service_name = match.groups()
                if status_symbol == '+':
                    running_services.append(service_name)
                elif status_symbol == '-':
                    stopped_services.append(service_name)
                else:
                    unknown_services.append(service_name)

        analysis = '<h3>Analysis of Service Status:</h3>'

        if running_services:
            analysis += '<p><strong>Running Services:</strong></p><ul>'
            for service in running_services:
                analysis += f'<li>{service}</li>'
            analysis += '</ul>'

        if stopped_services:
            analysis += '<p><strong>Stopped Services:</strong></p><ul>'
            for service in stopped_services:
                analysis += f'<li>{service}</li>'
            analysis += '</ul>'

        if unknown_services:
            analysis += '<p><strong>Services with Unknown Status:</strong></p><ul>'
            for service in unknown_services:
                analysis += f'<li>{service}</li>'
            analysis += '</ul>'

        return analysis

    except Exception as e:
        return f'An error occurred while analyzing service output: {str(e)}'

# New Log File Analyzer Function
def analyze_log_file(log_content):
    try:
        lines = log_content.strip().split('\n')

        if len(lines) == 0:
            return 'Log file content is empty or invalid.'

        error_keywords = ['error', 'fail', 'panic', 'fatal', 'critical']
        warning_keywords = ['warning', 'warn', 'deprecated']
        
        errors = []
        warnings = []

        for line in lines:
            lower_line = line.lower()
            # Check for errors
            if any(keyword in lower_line for keyword in error_keywords):
                errors.append(line)
            # Check for warnings
            elif any(keyword in lower_line for keyword in warning_keywords):
                warnings.append(line)

        # Generate a report
        analysis = '<h3>Log File Analysis:</h3>'

        if errors:
            analysis += '<p><strong>Errors Found:</strong></p><ul>'
            for error in errors:
                analysis += f"<li>{error}</li>"
            analysis += '</ul>'
        else:
            analysis += '<p>No errors found.</p>'

        if warnings:
            analysis += '<p><strong>Warnings Found:</strong></p><ul>'
            for warning in warnings:
                analysis += f"<li>{warning}</li>"
            analysis += '</ul>'
        else:
            analysis += '<p>No warnings found.</p>'

        return analysis

    except Exception as e:
        return f'An error occurred while analyzing the log file: {str(e)}'

if __name__ == '__main__':
    app.run(debug=True)
