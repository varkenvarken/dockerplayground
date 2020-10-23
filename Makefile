all:
	docker-compose build

authserver:
	docker-compose build authserver

up:
	docker-compose up -d

down:
	docker-compose down

flake:
	flake8 --ignore E501,E722,E221 `find . -name "*.py"|xargs`
