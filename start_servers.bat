@echo off
start "port5000" cmd /c "set PORT=5000 && python backend_server.py"
timeout /t 3 /nobreak >nul
start "port5001" cmd /c "set PORT=5001 && python backend_server.py"
timeout /t 3 /nobreak >nul
start "port5002" cmd /c "set PORT=5002 && python backend_server.py"
timeout /t 3 /nobreak >nul
start "port5003" cmd /c "set PORT=5003 && python backend_server.py"
timeout /t 5 /nobreak >nul
echo Done.
