@echo off
echo Adding things to the path...
set PATH=%PATH%;.
set PATH=%PATH%;c:\cygwin\bin

echo Setting up Visual Studio environment...
call "c:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat"

set WIRESHARK_TARGET_PLATFORM=win32

title Command Prompt (VC 2010 target x86)