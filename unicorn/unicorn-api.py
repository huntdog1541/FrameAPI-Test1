import binascii

from flask import Flask, request, jsonify
import sys

app = Flask(__name__)


@app.route('/')
def test():
    return 'Unicorn is running'


@app.route('/api')
def post_request():
    print('Request %s ' % request, file=sys.stderr)
    json = request.get_json()
    if json.get('architecture') is not None:
        print('Architecture %s ' % json.get('architecture'), file=sys.stderr)
    if json.get('mode') is not None:
        print('Mode %s ' % json.get('mode'), file=sys.stderr)
    if json.get('code') is not None:
        print('Code %s ' % json.get('code'), file=sys.stderr)
        code_bytes = binascii.unhexlify(json.get('code'))
        print('Bytes: %s ' % binascii.hexlify(code_bytes, '-'), file=sys.stderr)
    return 'Unicorn'


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')