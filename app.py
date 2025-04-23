from flask import Flask, render_template, request
from maps_api_scanner import scan_gmaps  # Import the scanner function

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    if request.method == 'POST':
        api_key = request.form['apikey']
        result = scan_gmaps(api_key)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)

