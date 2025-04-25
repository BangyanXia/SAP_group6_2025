from flask import Flask, request, render_template_string
import logging

app = Flask(__name__)

# Logging to file
logging.basicConfig(filename='web_honeypot.log', level=logging.INFO)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Router Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #eee; }
        .login-box {
            background-color: white;
            padding: 20px;
            width: 300px;
            margin: 100px auto;
            border-radius: 10px;
            box-shadow: 0 0 10px #aaa;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Router Login</h2>
        <form method="POST">
            <label>Username:</label><br>
            <input type="text" name="username"><br><br>
            <label>Password:</label><br>
            <input type="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr
        logging.info(f"Login attempt from {ip} - Username: {username}, Password: {password}")
    return render_template_string(HTML_PAGE)

if __name__ == "__main__":
    app.run(host="192.168.56.1", port=80)