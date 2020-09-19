from http.server import SimpleHTTPRequestHandler
from http import HTTPStatus

import mysql.connector


def create_table(mydb):
    tablename = 'log'

    mycursor = mydb.cursor()

    mycursor.execute("SHOW TABLES")
    tables = [row[0] for row in mycursor]

    if tablename not in tables:  
        mycursor.execute(f"CREATE TABLE {tablename} (  \
            id      INT AUTO_INCREMENT PRIMARY KEY,    \
            request VARCHAR(255),                      \
            status  VARCHAR(255),                      \
            address VARCHAR(30),                       \
            time    TIMESTAMP DEFAULT CURRENT_TIMESTAMP\
            )")

class LogHTTPRequestHandler(SimpleHTTPRequestHandler):
    
    def __init__(self, *args, mydb=None, **kwargs):
        self.mydb = mydb
        super().__init__(*args, **kwargs)

    def log_message(self, fstring, *args):
        # request code size as strings
        tablename = 'log'
        columns = 'request, status, address'
        positions = ','.join(['%s'] * len(columns.split(',')))

        sql = f"INSERT INTO {tablename} ({columns}) VALUES ({positions})"
        val = (args[0], args[1], self.client_address[0])
        print(sql, val)
        mycursor = self.mydb.cursor()
        mycursor.execute(sql, val)
        mydb.commit()

    def do_HEAD(self):
        print("HEAD", self.requestline)
        super().do_HEAD()

    def do_GET(self):
        print("GET", self.requestline)
        
        if self.requestline.startswith('GET /status '):
            mycursor = self.mydb.cursor()
            mycursor.execute("SELECT * FROM log ORDER BY id DESC LIMIT 20")
            result = mycursor.fetchall()
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            table = "<table><tr><th>ID</th><th>Request</th><th>Status</th><th>Address</th><th>Time</th></tr><tr><td>"+"</td></tr><tr><td>".join(["</td><td>".join([str(col) for col in row]) for row in result]) + "</td></tr>/<table>"
            html = f"""<html>
            <body>
            {table}
            </body>
            </html>
            """
            self.wfile.write(bytes(html,'utf-8'))
        else:
            super().do_GET()

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
    parser.add_argument('--loghost', '-l', default='localhost',
                        help='MySQL server [default:localhost]')
    parser.add_argument('--user', '-u', default='dbuser',
                        help='Database user [default:dbuser]')
    parser.add_argument('--password', '-p', default='secret',
                        help='Database password [default:secret]')
    parser.add_argument('--database', '-n', default='log_db',
                        help='Database name [default:log_db]')
    args = parser.parse_args()

    mydb = mysql.connector.connect(
        host=args.loghost,
        user=args.user,
        password=args.password,
        database=args.database
    )

    create_table(mydb)

    Handler = partial(LogHTTPRequestHandler, mydb=mydb, directory=args.directory)

    with socketserver.TCPServer(("", args.port), Handler) as httpd:
        print("serving at port", args.port)
        httpd.serve_forever()
