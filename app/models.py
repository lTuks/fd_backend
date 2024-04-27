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
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: str
    email: str
    password: str

    def create_user_db(user_data: dict):
        hashed_password = bcrypt.hashpw(user_data['password'].encode('utf-8'), bcrypt.gensalt())
        user_data['password'] = hashed_password
        db["users"].insert_one(user_data)

    def get_user_by_username(username: str):
        return db["users"].find_one({"username": username})

    def verify_password(plain_password, hashed_password):
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

class Piloto(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    nome: str
    numero: int
    notas: list[int] = []
    pontuacao: int = 0

    def create_piloto(cls, piloto_data: dict):
        db["pilotos"].insert_one(piloto_data)

    def get_piloto_by_nome(cls, nome: str):
        return db["pilotos"].find_one({"nome": nome})

    def update_pontuacao(cls, nome: str, novas_notas: list[int]):
        piloto = cls.get_piloto_by_nome(nome)
        if piloto:
            nova_pontuacao = sum(novas_notas) + piloto.get("pontuacao", 0)
            db["pilotos"].update_one({"nome": nome}, {"$set": {"pontuacao": nova_pontuacao, "notas": piloto.get("notas", []) + novas_notas}})
            return True
        return False
class Campeonato(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    classificacao: list[Piloto]

    def adicionar_piloto(cls, piloto_data: dict):
        db["campeonatos"].update_one({"_id": cls.id}, {"$push": {"classificacao": piloto_data}})

    def atualizar_pontuacao(cls, nome_piloto: str, novas_notas: list[int]):
        campeonato = db["campeonatos"].find_one({"_id": cls.id})
        if campeonato:
            for piloto in campeonato['classificacao']:
                if piloto['nome'] == nome_piloto:
                    updated_notas = piloto['notas'] + novas_notas
                    if len(updated_notas) > 6:
                        updated_notas = updated_notas[:6]
                    updated_pontuacao = sum(updated_notas) // len(updated_notas) if updated_notas else 0
                    db["campeonatos"].update_one({"_id": cls.id, "classificacao.nome": nome_piloto},
                                                  {"$set": {"classificacao.$.notas": updated_notas,
                                                            "classificacao.$.pontuacao": updated_pontuacao}})
                    break

    @classmethod
    def obter_classificacao(cls):
        campeonato = db["campeonatos"].find_one({"_id": cls.id})
        if campeonato:
            return sorted(campeonato['classificacao'], key=lambda x: x['pontuacao'], reverse=True)
        return []