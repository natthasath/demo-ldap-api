from fastapi import APIRouter, Depends, Form
from fastapi.responses import JSONResponse

router = APIRouter(
    prefix="/template",
    tags=["TEMPLATE"],
    responses={404: {"message": "Not found"}}
)

@router.get("/")
async def root():
    return {"message": "Hello World"}