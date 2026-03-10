@echo off
REM ============================================================================
REM GhidraMCP Build Script for Ghidra 12.0.4
REM ============================================================================
REM
REM Este script copia los JARs necesarios desde tu instalacion de Ghidra 12.0.4
REM y compila el plugin GhidraMCP.
REM
REM USO:
REM   build_for_ghidra12.bat "C:\ruta\a\ghidra_12.0.4_PUBLIC"
REM
REM REQUISITOS:
REM   - JDK 21 o superior instalado y en PATH
REM   - Maven instalado y en PATH (mvn)
REM   - Ghidra 12.0.4 descargado y descomprimido
REM ============================================================================

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo.
    echo ERROR: Necesitas especificar la ruta de tu instalacion de Ghidra 12.0.4
    echo.
    echo Uso: build_for_ghidra12.bat "C:\ruta\a\ghidra_12.0.4_PUBLIC"
    echo.
    exit /b 1
)

set GHIDRA_HOME=%~1

REM Verificar que la carpeta de Ghidra existe
if not exist "%GHIDRA_HOME%" (
    echo ERROR: La carpeta de Ghidra no existe: %GHIDRA_HOME%
    exit /b 1
)

echo.
echo ============================================
echo  GhidraMCP Builder para Ghidra 12.0.4
echo ============================================
echo.
echo Ghidra Home: %GHIDRA_HOME%
echo.

REM Crear directorio lib si no existe
if not exist lib mkdir lib

echo [1/3] Copiando JARs de Ghidra 12.0.4...

REM Copiar los JARs necesarios
set JARS_FOUND=0

REM Generic.jar
for /r "%GHIDRA_HOME%" %%f in (Generic.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Generic.jar >nul 2>&1
        echo   + Generic.jar
        set /a JARS_FOUND+=1
        goto :found_generic
    )
)
:found_generic

REM SoftwareModeling.jar
for /r "%GHIDRA_HOME%" %%f in (SoftwareModeling.jar) do (
    if exist "%%f" (
        copy "%%f" lib\SoftwareModeling.jar >nul 2>&1
        echo   + SoftwareModeling.jar
        set /a JARS_FOUND+=1
        goto :found_software
    )
)
:found_software

REM Project.jar
for /r "%GHIDRA_HOME%" %%f in (Project.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Project.jar >nul 2>&1
        echo   + Project.jar
        set /a JARS_FOUND+=1
        goto :found_project
    )
)
:found_project

REM Docking.jar
for /r "%GHIDRA_HOME%" %%f in (Docking.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Docking.jar >nul 2>&1
        echo   + Docking.jar
        set /a JARS_FOUND+=1
        goto :found_docking
    )
)
:found_docking

REM Decompiler.jar
for /r "%GHIDRA_HOME%" %%f in (Decompiler.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Decompiler.jar >nul 2>&1
        echo   + Decompiler.jar
        set /a JARS_FOUND+=1
        goto :found_decompiler
    )
)
:found_decompiler

REM Utility.jar
for /r "%GHIDRA_HOME%" %%f in (Utility.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Utility.jar >nul 2>&1
        echo   + Utility.jar
        set /a JARS_FOUND+=1
        goto :found_utility
    )
)
:found_utility

REM Base.jar
for /r "%GHIDRA_HOME%" %%f in (Base.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Base.jar >nul 2>&1
        echo   + Base.jar
        set /a JARS_FOUND+=1
        goto :found_base
    )
)
:found_base

REM Gui.jar
for /r "%GHIDRA_HOME%" %%f in (Gui.jar) do (
    if exist "%%f" (
        copy "%%f" lib\Gui.jar >nul 2>&1
        echo   + Gui.jar
        set /a JARS_FOUND+=1
        goto :found_gui
    )
)
:found_gui

echo.
echo   JARs encontrados: %JARS_FOUND% de 8

if %JARS_FOUND% LSS 8 (
    echo.
    echo ADVERTENCIA: No se encontraron todos los JARs necesarios.
    echo El build podria fallar. Verifica la ruta de Ghidra.
    echo.
)

echo.
echo [2/3] Compilando GhidraMCP con Maven...
echo.

call mvn clean package -q

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: La compilacion fallo. Revisa los errores arriba.
    exit /b 1
)

echo.
echo [3/3] Build completado!
echo.

REM Buscar el ZIP generado
for %%f in (target\GhidraMCP*.zip) do (
    echo   Extension ZIP: %%f
    echo.
    echo Para instalar en Ghidra:
    echo   1. Abri Ghidra
    echo   2. File ^> Install Extensions...
    echo   3. Click en + y selecciona: %%f
    echo   4. Reinicia Ghidra
    echo   5. En CodeBrowser: File ^> Configure ^> Miscellaneous
    echo   6. Activa GhidraMCPPlugin
    echo.
)

echo ============================================
echo  Build exitoso!
echo ============================================

endlocal
