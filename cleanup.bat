@echo off
echo ============================================
echo Cleaning up old codebase structure
echo ============================================

echo.
echo Deleting old files...

REM Delete old service files
del /Q "src\services\http_service.py" 2>nul
del /Q "src\services\timing_service.py" 2>nul
del /Q "src\services\analysis_service.py" 2>nul
del /Q "src\services\__init__.py" 2>nul

REM Delete old core files
del /Q "src\core\interfaces.py" 2>nul
del /Q "src\core\exceptions.py" 2>nul
del /Q "src\core\__init__.py" 2>nul

REM Delete old utils files
del /Q "src\utils\logger.py" 2>nul
del /Q "src\utils\stats.py" 2>nul
del /Q "src\utils\__init__.py" 2>nul

REM Delete old attack files
del /Q "src\attack\timing_attacker.py" 2>nul
del /Q "src\attack\__init__.py" 2>nul

REM Delete config directory
del /Q "config\config.yaml" 2>nul
rmdir "config" 2>nul

REM Remove empty directories
rmdir "src\services" 2>nul
rmdir "src\core" 2>nul
rmdir "src\utils" 2>nul
rmdir "src\attack" 2>nul

echo.
echo ============================================
echo Cleanup complete!
echo ============================================
echo.
echo New structure:
dir /B src\*.py
echo.
