from flask import Flask, render_template

from captcha import Captcha

app = Flask(__name__)

@app.route("/")
def home():
    demo = Captcha(7)
    return render_template("index.html", captcha=demo.get_captcha())

app.run(debug=True)
