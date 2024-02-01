from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def hello_world():
    return render_template("index.html", captcha="this is where the captcha will go!")

app.run(debug=True)
