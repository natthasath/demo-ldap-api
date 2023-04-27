from fastapi import Form
from pydantic import BaseModel, Field, EmailStr, SecretStr
from typing import List, Union
import inspect

def form_body(cls):
    cls.__signature__ = cls.__signature__.replace(
        parameters=[
            arg.replace(default=Form(default = arg.default) if arg.default is not inspect._empty else Form(...))
            for arg in cls.__signature__.parameters.values()
        ]
    )
    return cls

@form_body
class TemplateSchema(BaseModel):
    id: int = Field(default=None)

    class Config:
        schema_extra = {
            "example": {
                "id": "Incremental Number"
            }
        }