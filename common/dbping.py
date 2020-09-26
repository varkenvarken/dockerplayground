if __name__ == '__main__':
    import argparse
    import pymysql.cursors

    parser = argparse.ArgumentParser()
    parser.add_argument('--database', '-d', default='stuff')
    parser.add_argument('--host', '-s', default='localhost')
    parser.add_argument('--user', '-u', default='dbuser')
    parser.add_argument('--password', '-p', default='secret')
    args = parser.parse_args()


    # Connect to the database
    connection = pymysql.connect(host=args.host,
                                 user=args.user,
                                 password=args.password,
                                 db=args.database,
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)
