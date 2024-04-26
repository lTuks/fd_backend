#!/bin/bash
exec gunicorn -k uvicorn.workers.UvicornWorker -c gunicorn_config.py app.main:new_facility
