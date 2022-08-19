FROM python:3.6

ARG AES_KEY
ENV AES_KEY=$AES_KEY

COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]

CMD ["app.py"]