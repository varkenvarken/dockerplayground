all:
	docker-compose build

authserver:
	docker-compose build authserver

objectstore:
	docker-compose build objectstore

crawler:
	docker-compose build crawler

crudapp:
	docker-compose build crudapp

up:
	docker-compose up -d

down:
	docker-compose down

flake:
	flake8 --ignore E501,E722,E221 `find . -name "*.py"|xargs`

clean: down
	docker volume rm dockerplayground_userdata
	docker volume rm dockerplayground_data

.PHONY: authserver objectstore crawler crudapp

