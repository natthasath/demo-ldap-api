FROM python:3.9

WORKDIR /code

COPY ./poetry.lock /code/poetry.lock
COPY ./pyproject.toml /code/pyproject.toml
COPY ./.env /code/.env
COPY ./main.py /code/main.py
COPY ./app /code/app

COPY ./certs/localhost.crt /etc/ssl/certs/
COPY ./certs/localhost.key /etc/ssl/certs/

RUN pip install poetry
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

RUN sed -i 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1/' /etc/ssl/openssl.cnf \
&& sed -i 's/CipherString = DEFAULT@SECLEVEL=2/CipherString = DEFAULT@SECLEVEL=1/' /etc/ssl/openssl.cnf

HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:8000/docs || exit 1

CMD ["python", "main.py"]