import re
import logging
from flask import Flask, render_template, request, redirect, url_for, flash
import os

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session and flashing messages

# Define attack patterns with various injection techniques
class SimpleWAF:
    def __init__(self):
        self.rules = [
            re.compile(r'(union.*select.*from.*information_schema.tables)', re.IGNORECASE),  # SQL Injection
            re.compile(r'(select.*from.*information_schema.tables)', re.IGNORECASE),  # Variations of SQL Injection
            re.compile(r'<script.*>.*</script>', re.IGNORECASE),  # XSS (Script Tag)
            re.compile(r'javascript:.*', re.IGNORECASE),  # XSS (Javascript URLs)
            re.compile(r'(cat|ls|chmod|exec|bash).*', re.IGNORECASE),  # Command Injection
            re.compile(r'(Content-Length|Transfer-Encoding|Location):.*\r\n', re.IGNORECASE),  # HTTP Header Injection
        ]
        logging.basicConfig(filename='malicious_requests.log', level=logging.INFO,
                            format='%(asctime)s - %(message)s')

    def is_request_safe(self, request):
        for rule in self.rules:
            if rule.search(request):
                return False, rule.pattern
        return True, None

    def log_malicious_request(self, request, attack_type):
        logging.warning(f"Malicious request detected: {request}, Attack Type: {attack_type}")


# Initialize the WAF object
waf = SimpleWAF()

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        http_request = request.form["http_request"]
        
        if not http_request:
            flash("Please enter an HTTP request.", "warning")
            return redirect(url_for('home'))
        
        # Check if the request is safe
        is_safe, attack_type = waf.is_request_safe(http_request)
        
        if is_safe:
            flash("Request is safe.", "success")
        else:
            attack_type_description = get_attack_type_description(attack_type)
            flash(f"Malicious request detected!\nAttack Type: {attack_type_description}", "danger")
            waf.log_malicious_request(http_request, attack_type_description)
        
        return render_template("index.html")
    
    return render_template("index.html")


def get_attack_type_description(attack_type):
    """Return a more descriptive attack type"""
    if "union.*select" in attack_type:
        return "SQL Injection (Union Select)"
    elif "select.*from" in attack_type:
        return "SQL Injection (Select)"
    elif "<script.*>" in attack_type:
        return "XSS (Script Tag)"
    elif "javascript:" in attack_type:
        return "XSS (Javascript URL)"
    elif "cat|ls|chmod|exec" in attack_type:
        return "Command Injection"
    elif "Content-Length" in attack_type or "Transfer-Encoding" in attack_type:
        return "HTTP Header Injection"
    return "Unknown Attack"


@app.route("/log")
def view_log():
    """Display the malicious request log in the browser"""
    log_content = ""
    try:
        if os.path.exists('malicious_requests.log'):
            with open('malicious_requests.log', 'r') as log_file:
                log_content = log_file.read()
    except FileNotFoundError:
        log_content = "No log file found.\n"
    
    return render_template("log_viewer.html", log_content=log_content)


if __name__ == "__main__":
    app.run(debug=True)

