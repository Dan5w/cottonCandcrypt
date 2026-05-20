@echo off
setlocal enabledelayedexpansion

echo ================================================
echo  cottonCandcrypt - Setup inicial
echo ================================================
echo.

:: ── Entorno virtual ─────────────────────────────
if not exist "%~dp0venv\Scripts\python.exe" (
    echo [1/4] Creando entorno virtual...
    python -m venv "%~dp0venv"
    if errorlevel 1 (
        echo ERROR: No se pudo crear el entorno virtual. Verifica que Python este instalado.
        pause & exit /b 1
    )
) else (
    echo [1/4] Entorno virtual ya existe, omitiendo...
)

:: ── Dependencias ────────────────────────────────
echo [2/4] Instalando dependencias...
"%~dp0venv\Scripts\pip.exe" install -r "%~dp0requirements.txt" --quiet
if errorlevel 1 (
    echo ERROR: Fallo al instalar dependencias.
    pause & exit /b 1
)

:: ── Configuracion de credenciales (.env) ────────
echo [3/4] Configuracion de base de datos...
if exist "%~dp0.env" (
    echo    Archivo .env ya existe. Deseas reconfigurarlo?
    set /p RECONF="    Escribir S para reconfigurar, cualquier otra tecla para omitir: "
    if /i not "!RECONF!"=="S" goto :skip_env
)

echo.
echo    Ingresa las credenciales de tu base de datos MySQL:
echo.

set /p DB_HOST="    Host [localhost]: "
if "!DB_HOST!"=="" set DB_HOST=localhost

set /p DB_PORT="    Puerto [3306]: "
if "!DB_PORT!"=="" set DB_PORT=3306

set /p DB_USER="    Usuario [root]: "
if "!DB_USER!"=="" set DB_USER=root

set /p DB_PASS="    Contrasena: "

set /p DB_NAME="    Base de datos [backups0]: "
if "!DB_NAME!"=="" set DB_NAME=backups0

set /p DUMP_PATH="    Ruta a mysqldump.exe [C:\Program Files\MySQL\MySQL Server 9.2\bin\mysqldump.exe]: "
if "!DUMP_PATH!"=="" set "DUMP_PATH=C:\Program Files\MySQL\MySQL Server 9.2\bin\mysqldump.exe"

set /p MYCLI_PATH="    Ruta a mysql.exe [C:\Program Files\MySQL\MySQL Server 9.2\bin\mysql.exe]: "
if "!MYCLI_PATH!"=="" set "MYCLI_PATH=C:\Program Files\MySQL\MySQL Server 9.2\bin\mysql.exe"

(
    echo MYSQL_HOST=!DB_HOST!
    echo MYSQL_PORT=!DB_PORT!
    echo MYSQL_USER=!DB_USER!
    echo MYSQL_PASS=!DB_PASS!
    echo MYSQL_DB=!DB_NAME!
    echo MYSQLDUMP_PATH=!DUMP_PATH!
    echo MYSQL_PATH=!MYCLI_PATH!
    echo FLASK_SECRET_KEY=dbvault-secret-key-2024-change-in-production
) > "%~dp0.env"

echo.
echo    Archivo .env creado correctamente.

:skip_env

:: ── Base de datos ────────────────────────────────
echo [4/4] Inicializando base de datos...
"%~dp0venv\Scripts\python.exe" "%~dp0init_db.py"
if errorlevel 1 (
    echo ERROR: Fallo al inicializar la base de datos.
    echo Verifica que MySQL este corriendo y que las credenciales en .env sean correctas.
    pause & exit /b 1
)

echo.
echo ================================================
echo  Setup completado exitosamente.
echo  Para iniciar la aplicacion ejecuta:
echo    venv\Scripts\python.exe app.py
echo ================================================
pause
