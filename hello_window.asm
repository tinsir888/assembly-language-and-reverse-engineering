.386
.model flat, stdcall
option casemap :none
include .\masm32\include\windows.inc
include .\masm32\include\kernel32.inc
include .\masm32\include\user32.inc
includelib .\masm32\lib\kernel32.lib
includelib .\masm32\lib\user32.lib
.data
	str_hello BYTE "Servus!", 0
	str_headline BYTE "Guten Tag!", 0
.code
start:
	invoke MessageBox, NULL, addr str_headline, addr str_hello, MB_OK
	invoke ExitProcess, 0
END start