from typing import Final, Annotated
from datetime import timedelta, datetime
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from passlib.context import CryptContext  # bcrypt password hashing을 수행

# secret key must be keeped in secret(ex .env)
# can generate key via "openssl rand -hex 32"
ACCESS_TOKEN_SECRET_KEY: Final[str] = "7f13039fb7c2d98fbbc8440794c2b6c006e066909190c3d055f7c13475e5a052"
REFRESH_TOKEN_SECRET_KEY: Final[str] = "3b78bb05f22b376a2938a9483afccb5f5797b8611ede32004e735c19e6056245"

ALGORITHM: Final[str] = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: Final[int] = 1
REFRESH_TOKEN_EXPIRE_MINUTES: Final[int] = 1

# password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# header에 있는 bearer(access token)값 읽어와 토큰 값을 제공한다. 없다면 401 Not Authenticated
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

# for RTR
valid_refresh_list = []

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_token_data(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    """
    token의 payload를 리턴한다
    만약 oauth2_scheme에서 토큰 정보 가져올 수 없다면 401 Not Authenticated를 리턴할 것임
    """
    try:
        payload = jwt.decode(token, ACCESS_TOKEN_SECRET_KEY,
                             algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise credentials_exception


async def is_payload_valid(payload: Annotated[dict, Depends(get_token_data)]) -> True:
    """
    token 인증에서 사용자가 유효한지를 확인한다 (permission에서도 같은 로직 사용 가능)
    """
    invalid_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="This user is invalid",
    )
    # DB에서 payload['sub']에 해당하는 username이 있다면 유효한 사용자라고 판단
    validUserNameRow = [
        "helloworld",
        "hellowordl2",  # ...
    ]
    if payload["sub"] in validUserNameRow:
        return True
    else:
        raise invalid_exception


def verify_password(plain_password, hashed_password):
    """
    check password via pwd_context
    """
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    """
    check if username and password is valid,
    or return False
    """
    # DB에서 해당 username의 회원 정보 가져오는 로직 필요
    userRow = {
        "username": "helloworld",
        # https://bcrypt-generator.com/에서 '123456' 해싱한 것
        "hashed_password": "$2a$12$f/tQdnxJCXsuwDkY.XzuJeCyatnkxsYvkXmSyGR04QxuC39ZEVs3y"
    }
    if not verify_password(password, userRow["hashed_password"]):
        return False
    return userRow


def create_access_token(data: dict):
    """
    data : payload dictionary
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, ACCESS_TOKEN_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict):
    """
    data : payload dictionary
    refresh token을 생성하고, 변수로 해당 토큰을 저장한다
    """
    to_encode = data.copy()
    expire = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES) + \
        datetime.utcnow()
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, REFRESH_TOKEN_SECRET_KEY, algorithm=ALGORITHM)
    add_refresh_token(encoded_jwt)  # refresh token에 추가한다
    return encoded_jwt


def verify_refresh_token(token: str) -> dict:
    """
    해당 refresh 토큰이 유효한지 확인
    유효하다면 payload return
    """
    try:
        payload = jwt.decode(
            token, REFRESH_TOKEN_SECRET_KEY, algorithms=[ALGORITHM])
        if is_refresh_valid(token):
            return payload
    except JWTError:
        raise credentials_exception


def is_refresh_valid(token: str):
    """
    해당 토큰이 유효한 토큰 목록 변수에 있는지 확인
    """
    global valid_refresh_list
    return token in valid_refresh_list


def add_refresh_token(token: str):
    global valid_refresh_list
    valid_refresh_list.append(token)


def remove_refresh_token(token: str):
    global valid_refresh_list
    try:
        valid_refresh_list.remove(token)
    except:
        # list에 해당 토큰이 없는 경우
        raise credentials_exception
