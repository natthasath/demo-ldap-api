from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import template, ldap
from app.tag import SubTags, Tags

app = FastAPI(
    title="FastAPI",
    description="Web API helps you do awesome stuff. 🚀",
    version="0.0.1",
    terms_of_service="http://example.com/terms/",
    contact={
        "name": "Information and Digital Technology Center (IDT)",
        "url": "https://codeinsane.wordpress.com/",
        "email": "natthasath.sak@gmail.com",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    openapi_url="/api/v1/openapi.json",
    docs_url="/docs",
    openapi_tags=Tags(),
    swagger_ui_parameters={"defaultModelsExpandDepth": -1}
)

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ldap.router)
#
#
#

subapi = FastAPI(openapi_tags=SubTags(), swagger_ui_parameters={"defaultModelsExpandDepth": -1})

subapi.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

subapi.include_router(template.router)
#
#
#

app.mount("/subapi", subapi)