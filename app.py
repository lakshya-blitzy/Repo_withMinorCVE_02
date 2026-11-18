from flask import Flask
from werkzeug.serving import make_server

METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

app = Flask(__name__, static_folder=None)


@app.route('/', defaults={'p': ''}, methods=METHODS)
@app.route('/<path:p>', methods=METHODS)
def hello(p):
    return 'Hello, World!\n'


if __name__ == '__main__':
    server = make_server('127.0.0.1', 3000, app)
    print('Server running at http://127.0.0.1:3000/', flush=True)
    server.serve_forever()
