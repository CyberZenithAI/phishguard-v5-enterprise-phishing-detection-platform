# app/routes/web.py (CORREGIDO COMPLETO)

import os
import jwt

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")

web_router = APIRouter()

SECRET = os.getenv("JWT_SECRET", "fallback-secret")


@web_router.get("/", response_class=HTMLResponse)
async def home(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )


@web_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )


@web_router.post("/login")
async def login(
    username: str = Form(...),
    password: str = Form(...)
):

    if username == "admin" and password == "admin":

        token = jwt.encode(
            {"user": username},
            SECRET,
            algorithm="HS256"
        )

        response = RedirectResponse(
            url="/dashboard",
            status_code=302
        )

        response.set_cookie(
            key="token",
            value=token,
            httponly=True,
            secure=False,
            samesite="lax"
        )

        return response

    return RedirectResponse(
        url="/login",
        status_code=302
    )


@web_router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html"
    )


@web_router.get("/logout")
async def logout():

    response = RedirectResponse(
        url="/login",
        status_code=302
    )

    response.delete_cookie("token")

    return response
