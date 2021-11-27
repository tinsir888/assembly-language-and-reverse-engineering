.386
.model flat , stdcall
option casemap :none
include .\masm32\include\windows.inc
include .\masm32\include\kernel32.inc
include .\masm32\include\masm32.inc
includelib .\masm32\lib\kernel32.lib
includelib .\masm32\lib\masm32.lib

.data
	txt_nl byte 0Dh, 0Ah, 0
	txt_tab byte "    ", 0
	txt_input byte "Please input a PE file: ", 0
	txt_image_dos_header byte "IMAGE_DOS_HEADER", 0
	txt_image_nt_header byte "IMAGE_NT_HEADER", 0
	txt_image_file_header byte "IMAGE_FILE_HEADER", 0
	txt_image_optional_header byte "IMAGE_OPTIONAL_HEADER", 0
	filename byte 10h dup(0), 0
	txt_e_magic byte "e_magic(single word): ", 0
	txt_e_lfanew byte "e_lfanew: ", 0
	txt_signature byte "Signature: ", 0
	txt_numberofsections byte "NumberOfSections(single word): ", 0
	txt_timedatestamp byte "TimeDateStamp: ", 0
	txt_characteristics byte "Characteristics(single word): ", 0
	txt_addressofentrypoint byte "AddressOfEntryPoint: ", 0
	txt_imagebase byte "ImageBase: ", 0
	txt_sectionalignment byte "SectionAlignment: ", 0
	txt_filealignment byte "FileAlignment: ", 0
	buf dword 20000h dup(0)
	buf1 word 40000h dup(0)
	hfile dword 0
	hfile1 dword 0
	singleword word 0
.code
main proc
	invoke StdOut, addr txt_input
	invoke StdIn, addr filename, 10h
	invoke CreateFile, addr filename, GENERIC_READ, FILE_SHARE_READ,\
 0, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, 0
	mov hfile1, eax
	invoke SetFilePointer, hfile1, 0, 0, FILE_BEGIN
	invoke ReadFile, hfile1, addr buf1, 800000, 0, 0	
	mov hfile, eax
	invoke SetFilePointer, hfile, 0, 0, FILE_BEGIN
	invoke ReadFile, hfile, addr buf, 400000, 0, 0
	;mov eax, dword ptr buf;开头就是4D 5A 对应 MZ
	;and eax, 0FFFFh;取低字
	;invoke dw2hex, ax, addr singleword
	mov ax, word ptr buf1
	invoke dw2hex, ax, addr buf1
	;invoke dw2hex, eax, addr buf

	invoke StdOut, addr txt_image_dos_header
	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_e_magic
	invoke StdOut, addr buf1
	;invoke StdOut, addr singleword
	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_e_lfanew
	
	mov eax, dword ptr buf[3Ch];3Ch是e_lfanew在文件中的位置
	mov ebx, eax
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_image_nt_header
	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_signature

	mov eax, dword ptr buf[ebx];ebx存的是e_lfanew的值，是指向PE头文件的指针
	invoke dw2hex, eax, addr buf;PE头文件开始就存了signnature，值为4550h
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	;invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_image_file_header
	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_numberofsections

	add ebx, 6h;PE头文件signnature的6字节之后存的就是NumberOfSections
	mov eax, dword ptr buf[ebx]
	and eax, 0FFFFh;取低字
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_timedatestamp

	add ebx, 2h;PE头文件NumberOfSections的2字节之后存的就是时间戳
	mov eax, dword ptr buf[ebx]
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_characteristics

	add ebx, 0Eh;PE头文件时间戳的14字节之后存的就是characteristics
	mov eax, dword ptr buf[ebx]
	and eax, 0FFFFh;取低字
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	;invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_image_optional_header
	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_addressofentrypoint

	sub ebx, 16h
	add ebx, 28h; 第28h字节对应的是AddressOfEntryPoint
	mov eax, dword ptr buf[ebx]
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_imagebase

	sub ebx, 28h
	add ebx, 34h; 第34h字节对应的是ImageBase
	mov eax, dword ptr buf[ebx]
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_sectionalignment

	add ebx, 4h;第38h字节对应的是SectionAlignment
	mov eax, dword ptr buf[ebx]
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke StdOut, addr txt_tab
	invoke StdOut, addr txt_filealignment

	add ebx, 4h;第3Ch字节对应的是FileAlignment
	mov eax, dword ptr buf[ebx]
	invoke dw2hex, eax, addr buf
	invoke StdOut, addr buf

	invoke StdOut, addr txt_nl
	invoke CloseHandle, hfile
	ret
main endp
end main