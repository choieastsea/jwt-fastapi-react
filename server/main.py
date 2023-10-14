from typing import Annotated, Union
from fastapi import FastAPI, Response, Depends, status, HTTPException, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from auth import authenticate_user, create_access_token, create_refresh_token, get_token_data, is_payload_valid, verify_refresh_token, remove_refresh_token

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# OAuth2PasswordBearer의 tokenUrl과 같아야 swagger에서 권한 테스트가 용이
@app.post("/login/")
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # username을 payload의 sub(subject)로 넣는다
    access_token = create_access_token(data={"sub": user["username"]})
    refresh_token = create_refresh_token(data={"sub": user["username"]})
    # refresh token은 httponly cookie로 저장
    response.set_cookie(key='token', value=refresh_token, httponly=True)

    return {
        "access_token": access_token,
        "token_type": "Bearer"
    }


@app.post("/logout/")
async def logout(response: Response):
    response.delete_cookie(key='token', httponly=True)


@app.get("/payload/")
async def check_access_token(payload: Annotated[dict, Depends(get_token_data)]):
    """
    authenticated 되어있다면 payload data를 리턴
    아니라면 오류 발생
    """
    return {"data": payload}


@app.get("/authenticated/")
async def is_authenticated(authenticated: Annotated[bool, Depends(is_payload_valid)]):
    return {"data": "authenticated"}


@app.post("/refresh/")
async def refresh(response: Response, token: Union[str, None] = Cookie('')):
    """
    http only cookie에서 refresh_token 값을 얻어와 검증하고, 유효하다면 새로운 토큰을 발급한다
    """
    prev_token = token
    payload = verify_refresh_token(prev_token)
    remove_refresh_token(prev_token)
    refresh_token = create_refresh_token(payload)
    access_token = create_access_token(payload)
    response.set_cookie(key='token', value=refresh_token, httponly=True)
    return {
        "access_token": access_token,
        "token_type": "Bearer"
    }
