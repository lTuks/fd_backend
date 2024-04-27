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
    notas: Optional[list[float]]
    pontuacao: Optional[float]

    def create_pilot_db(pilot_data: dict):
        db["pilotos"].insert_one(pilot_data)

class Campeonato(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    nome: str
    seasion: int
    classificacao: Optional[list[Piloto]]

    def create_championship_db(championship_data: dict):
        db["campeonatos"].insert_one(championship_data)

    def insert_pilot_db(id, piloto_data: dict):
        db["campeonatos"].update_one({"_id": id}, {"$push": {"classificacao": piloto_data}})

    def update_score_db(id, nome_piloto: str, novas_notas: list[float]):
        campeonato = db["campeonatos"].find_one({"_id": id})
        if campeonato:
            for piloto in campeonato['classificacao']:
                if piloto['nome'] == nome_piloto:
                    piloto['notas'] = novas_notas
                    updated_pontuacao = sum(novas_notas) // len(novas_notas) if novas_notas else 0
                    db["campeonatos"].update_one({"_id": cls.id, "classificacao.nome": nome_piloto},
                                                  {"$set": {"classificacao.$.notas": novas_notas,
                                                            "classificacao.$.pontuacao": updated_pontuacao}})
                    break

    def get_ranking(id):
        campeonato = db["campeonatos"].find_one({"_id": id})
        if campeonato:
            return sorted(campeonato['classificacao'], key=lambda x: x['pontuacao'], reverse=True)
        return []