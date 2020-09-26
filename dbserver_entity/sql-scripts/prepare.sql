CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'dbuser'@'%' IDENTIFIED BY 'secret';
GRANT ALL PRIVILEGES ON entity.* TO 'dbuser'@'localhost';
GRANT ALL ON entity.* TO 'dbuser'@'%';
