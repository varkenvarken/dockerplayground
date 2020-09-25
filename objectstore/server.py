from http.server import SimpleHTTPRequestHandler
from http import HTTPStatus

class RESTHTTPRequestHandler(SimpleHTTPRequestHandler):
    
    def do_GET(self):
        print("GET", self.requestline)
        
        html=str(self.requestline)

        self.send_response(HTTPStatus.OK)
        self.end_headers()
            
        self.wfile.write(bytes('<gnerff/>','utf-8'))
        
if __name__ == '__main__':
    import argparse
    import os
    import http.server
    import socketserver
    from functools import partial

    parser = argparse.ArgumentParser()
    parser.add_argument('--bind', '-b', metavar='ADDRESS',
                        help='Specify alternate bind address '
                             '[default: all interfaces]')
    parser.add_argument('--directory', '-d', default=os.getcwd(),
                        help='Specify alternative directory '
                        '[default:current directory]')
    parser.add_argument('port', action='store',
                        default=8000, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8000]')
    args = parser.parse_args()

    Handler = partial(RESTHTTPRequestHandler, directory=args.directory)

    with socketserver.TCPServer(("", args.port), Handler) as httpd:
        print("serving at port", args.port)
        httpd.serve_forever()
