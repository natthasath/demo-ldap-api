import uvicorn
from decouple import config

if __name__ == "__main__":
    uvicorn.run("app.api:app", host=str(config("APP_HOST")), port=int(config("APP_PORT")), reload=True)
    # uvicorn.run("app.api:app", host=str(config("APP_HOST")), port=int(config("APP_PORT")), reload=True, ssl_certfile=config("SSL_CERTIFICATE"), ssl_keyfile=config("SSL_KEYFILE"))