from fastapi import Form
from pydantic import BaseModel, Field, EmailStr, SecretStr
from typing import List, Union
from enum import Enum
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
class ConfigSchema(BaseModel):
    ldap_host: str = Field(...)
    ldap_port: int = Field(...)
    ldap_ssl: bool = Field(...)
    ldap_user: str = Field(...)
    ldap_pass: SecretStr = Field(...)
    ldap_dn: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "ldap_host": "lab.local",
                "ldap_port": "389 or 636",
                "ldap_ssl": "False or True",
                "ldap_user": "apiadmin@lab.local",
                "ldap_pass": "password",
                "ldap_dn": "DC=lab,DC=local",
            }
        }

@form_body
class LoginSchema(BaseModel):
    username: EmailStr = Field(...)
    password: SecretStr = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "username": "username@lab.com",
                "password": "password"
            }
        }

@form_body
class OrganizationUnitSchema(BaseModel):
    ou_name: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "ou_name": "IT"
            }
        }

@form_body
class DistinguishedNameSchema(BaseModel):
    dn: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "dn": "IT"
            }
        }

@form_body
class SearchSchema(BaseModel):
    username: EmailStr = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "username": "username@lab.com"
            }
        }

@form_body
class ForgetPasswordSchema(BaseModel):
    username: EmailStr = Field(...)
    national_id: int  = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "username": "username@lab.com",
                "national_id": "1234567890123"
            }
        }

@form_body
class ResetPasswordSchema(BaseModel):
    username: EmailStr = Field(...)
    old_password: SecretStr  = Field(...)
    new_password: SecretStr  = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "username": "username@nlab.com",
                "old_password": "old password",
                "new_password": "new password"
            }
        }

@form_body
class ChangeOptionalSchema(BaseModel):
    username: EmailStr = Field(...)
    password: SecretStr  = Field(...)
    optional: str  = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "username": "username@nlab.com",
                "password": "password",
                "optional": "username@gmail.com"
            }
        }