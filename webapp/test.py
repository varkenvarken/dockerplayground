import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="dbuser",
  password="secret"
)

print(mydb)
