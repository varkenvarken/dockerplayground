CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'dbuser'@'%' IDENTIFIED BY 'secret';
GRANT ALL PRIVILEGES ON logging.* TO 'dbuser'@'localhost';
GRANT ALL ON logging.* TO 'dbuser'@'%';
