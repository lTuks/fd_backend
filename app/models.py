import os
from datetime import datetime
from typing import ClassVar, Optional

import bcrypt
from bson import ObjectId
from pydantic import BaseModel, Field
from pymongo import MongoClient

# Conexão com o MongoDB
URI = os.environ["MONGODB_URI"]
client = MongoClient(URI)
db = client["SCC_FD"]

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, values, **kwargs):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")


class User(BaseModel):
    username: str
    email: str
    password: str

    def create_user_db(user_data: dict):
        hashed_password = bcrypt.hashpw(user_data['password'].encode('utf-8'), bcrypt.gensalt())
        user_data['password'] = hashed_password
        user_collection.insert_one(user_data)

    def get_user_by_username(username: str):
        return user_collection.find_one({"username": username})

    def verify_password(plain_password, hashed_password):
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

class Piloto(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    nome: str
    numero: int
    notas: List[int] = []
    pontuacao: int = 0  # Pontuação inicial, atualizada pela média das notas

class Campeonato(BaseModel):
    classificacao: List[Piloto] = []

    def adicionar_piloto(self, piloto: Piloto):
        self.classificacao.append(piloto)

    def atualizar_pontuacao(self, nome_piloto: str, novas_notas: List[int]):
        for piloto in self.classificacao:
            if piloto.nome == nome_piloto:
                piloto.notas.extend(novas_notas)
                if len(piloto.notas) > 6:
                    piloto.notas = piloto.notas[:6]
                piloto.pontuacao = sum(piloto.notas) // len(piloto.notas) if piloto.notas else 0
                break

    def obter_classificacao(self) -> List[Piloto]:
        return sorted(self.classificacao, key=lambda x: x.pontuacao, reverse=True)