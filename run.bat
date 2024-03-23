@echo off

start /MIN venv\Scripts\python.exe server\main.py
venv\Scripts\python.exe client\main.py
pause