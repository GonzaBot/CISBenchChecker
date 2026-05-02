@echo off
setlocal

if exist venv\Scripts\python.exe (
    venv\Scripts\python.exe cisbench.py %*
) else (
    py -3 cisbench.py %*
)
