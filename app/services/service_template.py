from decouple import config
from fastapi.responses import JSONResponse

class TemplateService:
    def __init__(self):
        self.config = config("CONF_NAME")