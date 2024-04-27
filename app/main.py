import os
from datetime import datetime, timedelta

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from app.models import Campeonato, Piloto, PyObjectId, User, db

app = FastAPI()

SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = User.get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/")
async def home():
    return JSONResponse(status_code=status.HTTP_200_OK, content="OK")

@app.post("/users/", status_code=201)
def create_user(user: User, response: Response):
    User.create_user_db(user.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"username": user.username, "email": user.email}

@app.post("/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = User.get_user_by_username(form_data.username)
    if not user or not User.verify_password(form_data.password, user['password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/piloto", dependencies=[Depends(get_current_user)])
def create_pilot(piloto: Piloto):
    Piloto.create_pilot_db(piloto.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"piloto": piloto.nome, "numero": piloto.numero}

@app.post("/campeonato", dependencies=[Depends(get_current_user)])
def create_championship(campeonato: Campeonato):
    Campeonato.create_championship_db(campeonato.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"campeonato": campeonato.id}

@app.post("/campeonatos/{campeonato_id}/pilotos/")
def adicionar_piloto_a_campeonato(campeonato_id: PyObjectId, piloto_data: dict):
    campeonato = Campeonato(id=campeonato_id)
    campeonato.insert_pilot_db(piloto_data)
    return {"mensagem": "Piloto adicionado ao campeonato!"}

@app.put("/campeonatos/{campeonato_id}/pontuacao/")
def atualizar_pontuacao_de_piloto(campeonato_id: PyObjectId, nome_piloto: str, novas_notas: list[int]):
    campeonato = Campeonato(id=campeonato_id)
    campeonato.update_score_db(nome_piloto, novas_notas)
    return {"mensagem": "Pontuação do piloto atualizada!"}

@app.get("/campeonatos/{campeonato_id}/classificacao/")
def obter_classificacao(campeonato_id: PyObjectId):
    campeonato = Campeonato(id=campeonato_id)
    classificacao = campeonato.get_ranking()
    return {"classificacao": classificacao}