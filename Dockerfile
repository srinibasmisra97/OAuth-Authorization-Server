FROM python:3.8.3-slim-buster
RUN mkdir /src
WORKDIR /src
COPY ./ /src/
RUN pip install -r requirements.txt
CMD ["python", "main.py"]