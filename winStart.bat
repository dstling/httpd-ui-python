@echo off
setlocal

:: Create a temporary VBScript to run Python silently
set "vbsfile=%temp%\run_main_silent.vbs"

(
    echo Set WshShell = CreateObject("WScript.Shell"^)
    echo currentDirectory = WScript.Arguments.Item(0^)
    echo WshShell.CurrentDirectory = currentDirectory
    echo WshShell.Run "python main.py", 0, False
) > "%vbsfile%"

:: Run the VBScript silently
cscript //nologo "%vbsfile%" "%~dp0"

:: Clean up
del "%vbsfile%" > nul 2>&1
endlocal