# OAuth Auth Server

This project is a simple implementation of an OAuth Authorization Server.

Tools used:
1. [Python3](https://www.python.org/downloads/)
2. [MongoDb](https://docs.mongodb.com/manual/installation/)
3. [Memcache](https://memcached.org/downloads)

## Run the server

### Using docker-compose

Tools needed:
1. [Docker](https://docs.docker.com/get-docker/)
2. [Docker-Compose](https://docs.docker.com/compose/install/)

In the project-folder, run the command:
```
docker-compose up
```

### Without docker

1. Setup MongoDb.
2. Setup Memcached.
3. Update the ./environment.cfg file in the ./configs directory.

Create a virtualenv for Python3 and install the dependencies.
```
pip install -r requirements.txt
```

Start the server:
```
python main.py
```