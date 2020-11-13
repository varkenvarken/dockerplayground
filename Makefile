all:
	docker-compose build

authserver:
	docker-compose build authserver

objectstore:
	docker-compose build objectstore

crawler:
	docker-compose build crawler

frontend:
	docker-compose build frontend

up:
	docker-compose up -d

down:
	docker-compose down

flake:
	flake8 --ignore E501,E722,E221,E241 `find . -name "*.py"|xargs`

clean: down
	docker volume rm dockerplayground_userdata
	docker volume rm dockerplayground_data

testauthserver:
	(cd authserver; ./test_authserver)

.PHONY: authserver objectstore crawler frontend testauthserver

