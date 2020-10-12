if __name__ == '__main__':
    from os import environ
    import pymysql.cursors

    password = environ['MYSQL_ROOT_PASSWORD'] if 'MYSQL_ROOT_PASSWORD' in environ else None
    database = environ['MYSQL_DATABASE'] if 'MYSQL_DATABASE' in environ else 'default'
    user = environ['MYSQL_USER'] if 'MYSQL_USER' in environ else 'default'
    server = environ['MYSQL_SERVER'] if 'MYSQL_SERVER' in environ else 'localhost'
    if password is None and 'MYSQL_ROOT_PASSWORD_FILE' in environ:
        with open(environ['MYSQL_ROOT_PASSWORD_FILE']) as f:
            password = f.read().strip()

    # Connect to the database
    connection = pymysql.connect(host=server,
                                 user=user,
                                 password=password,
                                 db=database,
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)
