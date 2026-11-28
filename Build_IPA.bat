@echo off
title PHUCVN IPA DEV - Build IPA Tool
cd /d "%~dp0"

python build_ipa.py
if %errorlevel% neq 0 (
    echo.
    echo [Loi] Chuong trinh bi dung dot ngot voi ma loi: %errorlevel%
)
pause