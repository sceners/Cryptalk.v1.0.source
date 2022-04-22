
include windows.inc
include kernel32.inc
include user32.inc
include Comctl32.inc
include shell32.inc
include wsock32.inc
include gdi32.inc

includelib kernel32.lib
includelib user32.lib
includelib Comctl32.lib
includelib shell32.lib
includelib wsock32.lib
includelib gdi32.lib

DlgProc			PROTO	:HWND,:UINT,:WPARAM,:LPARAM

.const

dlgCryptalk						equ 101
edtMainChat						equ 1001
lstUsers						equ 1002
edtToSend						equ 1003
btnCreateServer					equ 1004
ipaConnectTo					equ 1005
btnSend							equ 1006
btnConnect						equ 1007
ipaYourIP						equ 1008
btnAbout						equ 1009
stcYourIP						equ 1010
stcConnectTo					equ 1011
edtMyNick						equ 1012
icoSnow							equ 50

WM_SOCKET						equ WM_USER+1

;#########################################################################

.data?

hInstance			dd	?
iccex				INITCOMMONCONTROLSEX <?>
wsadata				WSADATA <?>
yourHost			db	256 dup (?)
yourIP				dd	?
serverIP			dd	?
hSock1				dd	?
SA1					sockaddr_in <?>
hSock2				dd	?
SA2					sockaddr_in <?>
hMainChat			dd	?
readBuffer			db	10*1024 dup (?)
oneMsg				db	2*1024 dup (?)
editSend			db	1024 dup (?)
sendBuffer			db	2*1024 dup (?)
acceptedSockets		db	4*50 dup (?)
numberOfSockets		dd	?
acceptedNicks		db	64*50 dup (?)
myNick				db	64 dup (?)
mainChat			db	128*1024 dup (?)
showmynick			dd	?
isServerOn			dd	?
isConnected			dd	?
systime				SYSTEMTIME <?>
currentTime			db	64 dup (?)

;#########################################################################

.data

aboutTxt			db	"Cryptalk v1.0",13,10,13,10
					db	"Completed on o8.o4.2oo6",13,10
					db	"coded in win32asm by FiNS//HTBTeam",13,10,13,10
					db	"All rights reserved.",0
aboutCap			db	"About Cryptalk",0
nickForm			db	"nic:%s",0
textForm			db	"txt:%s",0
msgToShowForm		db	"txt:<%s> %s",0
joinsForm			db	"joi:Joins: %s",0
partsForm			db	"par:Parts: %s",0
userForm			db	"usr:%s",0
timeForm			db	"[%02d:%02d] ",0
zero				dd	0
createServer		db	"Create server",0
stopServer			db	"Stop server",0
sConnect			db	"Connect",0
sDisconnect			db	"Disconnect",0
serverStarted		db	"*** Server started ***",0
serverStopped		db	"*** Server stopped ***",0
connecting			db	"*** Connecting to server ***",0
disconnected		db	"*** Disconnected from server ***",0
bufferCleared		db	"*** Buffer cleared ***",0
toManyConnections	db	"*** Sorry, but there are already to many connections ***",0
crlf				db	13,10,0