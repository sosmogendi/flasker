from flask import Flask, render_template

# Create flask instance
app = Flask(__name__)

# Create a route decorator
@app.route('/')
#def index():
#   return "<h2>Started</h2>"

def index():
    return render_template("index.html")


#localhost:5000/user/john
@app.route("/user/<name>")
def user(name):
    return render_template("user.html", name=name)

#custom error pages

#Invalid url
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Error handler for 500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

