from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from app.models.model_ldap import ConfigSchema, LoginSchema, OrganizationUnitSchema, DistinguishedNameSchema, SearchSchema, ForgetPasswordSchema, ResetPasswordSchema, ChangeOptionalSchema
from app.services.service_ldap import LdapService

router = APIRouter(
    prefix="/ldap",
    tags=["LDAP"],
    responses={404: {"message": "Not found"}}
)

@router.post("/config")
async def config(data: ConfigSchema = Depends(ConfigSchema)):
    return LdapService().config(data.ldap_host, data.ldap_port, data.ldap_ssl, data.ldap_user, data.ldap_pass.get_secret_value(), data.ldap_dn)

@router.post("/auth")
async def user_login(request: Request, data: LoginSchema = Depends(LoginSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    return LdapService().auth(ldap_host, ldap_port, ldap_ssl, data.username, data.password.get_secret_value())

@router.post("/ou")
async def all_ous(request: Request, data: OrganizationUnitSchema = Depends(OrganizationUnitSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().all_ous(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.ou_name)

@router.post("/group")
async def all_groups(request: Request, data: OrganizationUnitSchema = Depends(OrganizationUnitSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().all_groups(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.ou_name)

@router.post("/user")
async def all_users(request: Request, data: OrganizationUnitSchema = Depends(OrganizationUnitSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().all_users(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.ou_name)

@router.post("/user/ou")
async def ou_users(request: Request, data: DistinguishedNameSchema = Depends(DistinguishedNameSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().ou_users(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.dn)

@router.post("/user/search")
async def search_user(request: Request, data: SearchSchema = Depends(SearchSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().search_user(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.username)

@router.post("/user/memberof")
async def memberof_user(request: Request, data: SearchSchema = Depends(SearchSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().memberof_user(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.username)

@router.get("/user/status")
async def status_user():
    return LdapService().status_user()

@router.post("/forget/password")
async def forget_password(request: Request, data: ForgetPasswordSchema = Depends(ForgetPasswordSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_user = request.cookies.get("ldap_user")
    ldap_pass = request.cookies.get("ldap_pass")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().forget_password(ldap_host, ldap_port, ldap_ssl, ldap_user, ldap_pass, ldap_dn, data.username, data.national_id)

@router.patch("/reset/password")
async def reset_password(request: Request, data: ResetPasswordSchema = Depends(ResetPasswordSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().reset_password(ldap_host, ldap_port, ldap_ssl, ldap_dn, data.username, data.old_password.get_secret_value(), data.new_password.get_secret_value())

@router.patch("/change/optional")
async def change_optional(request: Request, data: ChangeOptionalSchema = Depends(ChangeOptionalSchema)):
    ldap_host = request.cookies.get("ldap_host")
    ldap_port = request.cookies.get("ldap_port")
    ldap_ssl = request.cookies.get("ldap_ssl")
    ldap_dn = request.cookies.get("ldap_dn")
    return LdapService().change_optional(ldap_host, ldap_port, ldap_ssl, ldap_dn, data.username, data.password.get_secret_value(), data.optional)