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
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

