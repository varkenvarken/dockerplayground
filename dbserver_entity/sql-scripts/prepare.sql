CREATE USER 'dbuser'@'localhost' IDENTIFIED BY 'secret';
CREATE USER 'dbuser'@'%' IDENTIFIED BY 'secret';
GRANT ALL PRIVILEGES ON log_entity.* TO 'dbuser'@'localhost';
GRANT ALL ON log_entity.* TO 'dbuser'@'%';
