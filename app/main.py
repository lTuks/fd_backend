import os
from datetime import datetime, timedelta

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from unidecode import unidecode

from app.models import Campeonato, Piloto, PontuacaoInput, PyObjectId, User, db

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=["token"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.get("/", status_code=200)
def home(response: Response):
    response.status_code = status.HTTP_200_OK
    return {"Mensagem": "Ok"}

@app.post("/users/", status_code=201)
def create_user(user: User, response: Response):
    User.create_user_db(user.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"username": user.username}

@app.post("/login", status_code=200)
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

@app.post("/piloto", dependencies=[Depends(get_current_user)], status_code=201)
def create_pilot(piloto: Piloto, response: Response):
    Piloto.create_pilot_db(piloto.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"piloto": piloto.nome, "numero": piloto.numero}

@app.get("/piloto/{nome_piloto}", dependencies=[Depends(get_current_user)], status_code=201)
def get_one_pilot(nome_piloto: str):
    pilots = []
    pilots_filter = []

    for pilot in db["pilotos"].find():
        pilots.append(Piloto(**pilot))
    pilots = jsonable_encoder(pilots)
    
    for i in range(len(pilots)):
        if id in unidecode(pilots[i]["nome"]).lower():
            pilots_filter.append(pilots[i]) 
    return {"piloto": pilot}

@app.get("/pilotos/", dependencies=[Depends(get_current_user)], status_code=200)
def get_pilotos(response: Response):
    pilots = Piloto.get_pilots_db()
    return {"pilotos": pilots}

@app.post("/campeonato", dependencies=[Depends(get_current_user)], status_code=201)
def create_championship(campeonato: Campeonato, response: Response):
    Campeonato.create_championship_db(campeonato.dict(by_alias=True))
    response.status_code = status.HTTP_201_CREATED
    return {"campeonato": campeonato.nome}

@app.get("/campeonato/")
def get_Championships(response: Response):
    championships = []
    for championship in db["campeonatos"].find({"status": True}):
        championships.append(Campeonato(**championship))
    championships = jsonable_encoder(championships)
    return JSONResponse(status_code=status.HTTP_200_OK, content=championships)

@app.post("/campeonatos/{campeonato_id}/pilotos/", dependencies=[Depends(get_current_user)], status_code=201)
def adicionar_piloto_a_campeonato(campeonato_id: PyObjectId, piloto_data: dict, response: Response):
    Campeonato.insert_pilot_db(campeonato_id, piloto_data)
    response.status_code = status.HTTP_201_CREATED
    return {"mensagem": "Piloto adicionado ao campeonato!"}

@app.put("/campeonatos/{campeonato_id}/pontuacao/", dependencies=[Depends(get_current_user)], status_code=201)
def atualizar_pontuacao_de_piloto(campeonato_id: PyObjectId, nome_piloto: str, dados: PontuacaoInput, response: Response):
    Campeonato.update_score_db(campeonato_id, nome_piloto, dados.novas_notas)
    response.status_code = status.HTTP_201_CREATED
    return {"mensagem": "Pontuação do piloto atualizada!"}

@app.put("/campeonatos/{campeonato_id}/", dependencies=[Depends(get_current_user)], status_code=201)
def finalizar_campeonato(campeonato_id: PyObjectId, response: Response):
    Campeonato.finish_championship(campeonato_id, )
    response.status_code = status.HTTP_200_OK
    return {"mensagem": "Campeonato Encerrado!"}

@app.get("/campeonatos/{campeonato_id}/classificacao/", status_code=200)
def obter_classificacao(campeonato_id: PyObjectId, response: Response):
    classificacao = Campeonato.get_ranking(campeonato_id)
    response.status_code = status.HTTP_200_OK
    return {"classificacao": classificacao}