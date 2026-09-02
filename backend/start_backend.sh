#!/usr/bin/env bash
export PYTHONUNBUFFERED=1
export CUDA_VISIBLE_DEVICES="-1"
export TF_CPP_MIN_LOG_LEVEL="3"
cd /mnt/c/Users/LENOVO/SENTRi-X
source wsl_venv/bin/activate
cd backend
python -u -m uvicorn main:app --host 0.0.0.0 --port 8000
