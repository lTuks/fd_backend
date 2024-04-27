import os
from datetime import datetime, timedelta

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from app.models import Campeonato, Piloto, User, db

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

@app.post("/users/", status_code=201)
def create_user(user: User, response: Response):
    User.create_user_db(user.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"username": user.username, "email": user.email}

@app.post("/token")
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

@app.post("/pilotos/", dependencies=[Depends(get_current_user)])
def adicionar_piloto(piloto: Piloto):
    piloto_instance = Piloto(**piloto.dict(by_alias=True))
    piloto_instance.create_piloto(piloto.dict(by_alias=True))
    return {"msg": f"Piloto {piloto.nome} adicionado com sucesso."}

@app.patch("/pilotos/{nome_piloto}", dependencies=[Depends(get_current_user)])
def atualizar_pontuacao(nome_piloto: str, novas_notas: list[int], current_user: User = Depends(get_current_user)):
    sucesso = Piloto.update_pontuacao(nome_piloto, novas_notas)
    if sucesso:
        return {"msg": f"Notas atualizadas e nova pontuação calculada para {nome_piloto}."}
    else:
        raise HTTPException(status_code=404, detail="Piloto não encontrado")

@app.get("/classificacao/")
def obter_classificacao():
    classificacao = Campeonato.obter_classificacao()
    return {"classificacao": classificacao}

@app.post("/campeonatos/", dependencies=[Depends(get_current_user)])
def criar_campeonato(campeonato: Campeonato):
    existing_campeonato = db["campeonatos"].find_one({"_id": campeonato.id})
    if existing_campeonato:
        raise HTTPException(status_code=400, detail="Campeonato já existe")
    db["campeonatos"].insert_one(campeonato.dict(by_alias=True))
    return {"msg": f"Campeonato criado com sucesso, ID: {campeonato.id}"}