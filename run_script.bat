del zepv3.dll

nmake -f Makefile.nmake distclean

nmake -f Makefile.nmake all

copy zepv3.dll "c:\wireshark-1.12.0-win64\wireshark-gtk2\plugins\1.12.0\zepv3.dll"

PAUSE

start "" "c:\wireshark-1.12.0-win64\wireshark-gtk2\wireshark.exe" "d:\Dokumenty\UWB\Mereni\timestamp.txt"
