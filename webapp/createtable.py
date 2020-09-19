import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="dbuser",
  password="secret",
  database="log_db"
)

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
