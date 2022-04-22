; -----------------------------------------------------------------------
;                             Cryptalk v1.0
;                            by FiNS//HTBTeam
;                        Completed on o8.o4.2oo6
; -----------------------------------------------------------------------
; Prog napisany w celach edukacyjnych. Komentarze napisane w taki sposob
; aby ktos, kto nie ma zielonego pojecia o assemblerze mogl to zrozumiec.
; Jak jestes nieco obeznany w temacie, to niektore moga nawet smieszyc ;)
; -----------------------------------------------------------------------

.486
.model flat, stdcall	;32 bit memory model
option casemap :none	;case sensitive

include cryptalk.inc

.code

start:
;Start programu, inicjalizacja niestandardowej kontrolki IPAddress,
;wywolanie procedury glownego okna programu.

	invoke GetModuleHandle,NULL
	mov		hInstance,eax
	invoke InitCommonControls
	mov		iccex.dwSize,sizeof INITCOMMONCONTROLSEX
	mov		iccex.dwICC,ICC_INTERNET_CLASSES
	invoke InitCommonControlsEx,addr iccex
	invoke DialogBoxParam,hInstance,dlgCryptalk,NULL,addr DlgProc,NULL
	invoke ExitProcess,0

;########################################################################

GetNickFromSocket proc uses ebx, socketToFind:DWORD
;Funkcja znajdujaca w tablicy nickow nick, ktory odpowiada podanemu
;w parametrze socketowi. Wskaznik do znalezionego nicka zwracany
;jest w rejestrze eax.

	mov		eax, offset acceptedSockets
	mov		ebx, socketToFind
	.while dword ptr [eax]!=ebx
		add eax, 4
	.endw
	sub		eax, offset acceptedSockets
	shr		eax, 2
	imul	eax, eax, 64
	add		eax, offset acceptedNicks
	ret

GetNickFromSocket endp

Encrypt proc uses eax ecx esi edi buffer:DWORD, bufSize:DWORD
;Procedura szyfrujaca ilosc bajtow podana w bufSize z bufora buffer.
;Szyfrowanie polega na przesunieciu kazdego znaku o 7 pozycji zgodnie
;z idea algorytmu szyfrujacego cezara, nastepnie kazdy bajt xorowany
;(alternatywa wykluczajaca) jest z wartoscia 77, a nastepnie wykonywana
;jest na nim operacja negacji logicznej.

	mov		ecx, bufSize
	mov		esi, buffer
	mov		edi, esi
	.while ecx!=0
		lodsb
		add		al, 7
		xor		al, 77
		not		al
		stosb
		dec		ecx
	.endw
	ret

Encrypt endp

Decrypt proc uses eax ecx esi edi buffer:DWORD, bufSize:DWORD
;Procedura deszyfrujaca ilosc bajtow podana w bufSize z bufora buffer.
;Deszyfrowanie jest odwroconym algorytem szyfrowania (najpierw negacja
;logiczna, potem xorowanie i ostatecznie przesuniecie znakow w przeciwna
;strone).

	mov		ecx, bufSize
	mov		esi, buffer
	mov		edi, esi
	.while ecx!=0
		lodsb
		not		al
		xor		al, 77
		sub		al, 7
		stosb
		dec		ecx
	.endw
	ret

Decrypt endp

ServerSendToAll proc uses eax ecx edx buffer:DWORD
;Procedura wysylajaca wiadomosc znajdujaca sie w buffer od serwera
;do wszystkich polaczonych klientow.

	invoke lstrlen,buffer
	inc		eax
	invoke Encrypt,buffer,eax
	mov		edx, offset acceptedSockets
	mov		ecx, numberOfSockets
	.while ecx!=0
		pusha
		invoke send,[edx],buffer,eax,0
		popa
		add		edx, 4
		dec		ecx
	.endw
	ret

ServerSendToAll endp

SendToServer proc uses eax ecx edx buffer:DWORD
;Procedura wysylajaca wiadomosc znajdujaca sie w buffer od klienta
;do serwera.

	invoke lstrlen,buffer
	inc		eax
	invoke Encrypt,buffer,eax
	invoke send,hSock2,buffer,eax,0	
	ret

SendToServer endp

AddToMainChat proc uses eax ecx edx buffer:DWORD
;Procedura ktora dodaje do mainChat linijke postaci: [godz:min] buffer
;a nastepnie wyswietla dodany tekst i przewija pole edycyjne w dol.
;Przy kazdym dodawaniu linijki sprawdzane jest, czy dane z mainChat nie
;przekraczaja rozmiaru tego bufora, jesli tak, to jest on czyszczony.

	invoke GetLocalTime,addr systime
	xor		eax, eax
	push	ax
	push	systime.wMinute
	push	ax
	push	systime.wHour
	push	offset timeForm
	push	offset currentTime
	call	wsprintf
	add		esp,4*4
	invoke lstrlen,addr mainChat
	.if eax>126*1024
		mov		eax, offset mainChat
		mov		dword ptr [eax], 0
		invoke lstrcat,addr mainChat,addr bufferCleared
	.endif
	invoke lstrcat,addr mainChat,addr crlf
	invoke lstrcat,addr mainChat,addr currentTime
	invoke lstrcat,addr mainChat,buffer
	invoke SetWindowText,hMainChat,addr mainChat
	invoke SendMessage,hMainChat,WM_VSCROLL,SB_BOTTOM,0
	ret

AddToMainChat endp

GetMsgNumber proc uses ecx esi buffer:DWORD, bufSize:DWORD
;Funkcja zliczajaca ile wiadomosci zakonczonych znakiem null znajduje
;sie w buforze buffer o rozmiarze bufSize. Liczba wiadomosci zwracana
;jest w rejestrze eax.

	mov		ecx, bufSize
	mov		esi, buffer
	xor		eax, eax
	.while ecx!=0
		.if byte ptr [esi]==0
			inc		eax
		.endif
		inc		esi
		dec		ecx
	.endw
	ret

GetMsgNumber endp

GetOneMsgFromPos proc uses eax ecx edx esi dstBuffer:DWORD,srcBuffer:DWORD,number:DWORD
;Procedura ktora kopiuje wiadomosc o numerze number, zakonczona znakiem 
;null z srcBuffer do dstBuffer. Pierwsza wiadomosc indeksowana jest jako 1

	mov		esi, srcBuffer
	mov		ecx, number
	dec		ecx
	.while ecx!=0
		.if byte ptr [esi]==0
			dec ecx
		.endif
		inc		esi
	.endw
	invoke lstrcpy,dstBuffer,esi
	ret

GetOneMsgFromPos endp

DeleteUser proc uses eax ecx edi socketToDelete:DWORD
;Procedura usuwajaca podany socket i odpowiadajacy mu nick z tablic
;acceptedSockets i acceptedNicks. Zmniejsza tez liczbe socketow
;w numberOfSockets o 1. Usuwanie polega na przesunieciu wszystkich
;elementow tablicy znajdujacych sie za elementem do skasowania tak,
;by w srodku tablicy nie zostaly puste pola.

;przesuwanie nickow
	invoke GetNickFromSocket,socketToDelete
	mov		ecx, eax
	add		ecx, 64
	.while ecx<(offset acceptedNicks+sizeof acceptedNicks)
		push	dword ptr [ecx]
		pop		dword ptr [eax]
		add		eax, 4
		add		ecx, 4
	.endw
;czyszczenie pola z ostatnim nickiem
	mov		edi, eax
	xor		eax, eax
	mov		ecx, 64
	rep		stosb

;przesuwanie socketow
	mov		eax, offset acceptedSockets
	mov		ecx, socketToDelete
	.while dword ptr [eax]!=ecx
		add		eax, 4
	.endw
	mov		ecx, eax
	add		ecx, 4
	.while ecx<(offset acceptedSockets+sizeof acceptedSockets)
		push	dword ptr [ecx]
		pop		dword ptr [eax]
		add		eax, 4
		add		ecx, 4
	.endw
;czyszczenie pola z ostatnim socketem
	mov		dword ptr [eax], 0

	dec		numberOfSockets
	ret

DeleteUser endp

DlgProc proc uses esi edi ebp ebx hWin:HWND,uMsg:UINT,wParam:WPARAM,lParam:LPARAM
;Procedura obslugujaca zdarzenia okna dialogowego.

	mov		eax,uMsg
	.if eax==WM_INITDIALOG
;Obsluga zdarzenia WM_INITDIALOG - wiadomosc wysylana przy inicjalizowaniu okna.
;Inicjalizacja biblioteki winsock do komunikacji sieciowej, pobranie
;i wyswietlanie wlasnego IP, ograniczanie pola wysylanej wiadomoci do 1000
;znakow, wyswietlanie ikony programu na pasku tytulowym.
		invoke WSAStartup,101h,addr wsadata
		invoke gethostname,addr yourHost, 256
		invoke gethostbyname,addr yourHost
		mov		eax,[eax+12]
		mov		eax,[eax]
		mov		eax,[eax]
		mov		yourIP, eax
		bswap	eax
		push	eax
		invoke SendDlgItemMessage,hWin,ipaYourIP,IPM_SETADDRESS,0,eax
		pop		eax
		invoke SendDlgItemMessage,hWin,ipaConnectTo,IPM_SETADDRESS,0,eax
		invoke SendDlgItemMessage,hWin,edtToSend,EM_SETLIMITTEXT,1000,0
		invoke GetDlgItem,hWin,edtMainChat
		mov		hMainChat, eax
		invoke LoadIcon,hInstance,icoSnow
		invoke SendMessage,hWin,WM_SETICON,ICON_BIG,eax
	.elseif eax==WM_CTLCOLORSTATIC
;WM_CTLCOLORSTATIC - wiadomosc umozliwiajaca zmiane kolorow danej kontrolki
		mov		eax, hMainChat
		.if lParam==eax
;Glowne pole z wiadomosciami domyslnie wyswietlane jest na szaro gdyz ma
;wlasciwosc readonly, wiec ustawiamy jego kolor na bialy.
			invoke GetStockObject,WHITE_BRUSH
			ret
		.endif
	.elseif eax==WM_COMMAND
;WM_COMMAND - wiadomosc wysylana w przypadku klikniecia jakiejs kontrolki.
		.if wParam==btnAbout
;Nacisniecie przycisku About pokazuje okno informacyjne.
			invoke MessageBox,hWin,addr aboutTxt,addr aboutCap,MB_ICONINFORMATION
		.elseif wParam==btnCreateServer
			.if isServerOn==0
;Nacisniecie przycisku Create server tworzy serwer nasluchujacy na porcie 2323.
;Wiadomosc o utworzeniu serwera pokazujemy na polu z czatem i zmieniamy napis
;na przycisku na Stop server.
				invoke socket,AF_INET,SOCK_STREAM,IPPROTO_TCP
				mov		hSock1,eax
				invoke WSAAsyncSelect,eax,hWin,WM_SOCKET,FD_ACCEPT
				invoke htons,2323
				mov		SA1.sin_port,ax
				mov		SA1.sin_addr.S_un.S_addr,INADDR_ANY
				mov		SA1.sin_family,AF_INET
				invoke bind,hSock1,addr SA1,16
				invoke listen,hSock1,1
				invoke SetDlgItemText,hWin,btnCreateServer,addr stopServer
				invoke AddToMainChat,addr serverStarted
				mov		isServerOn, 1
			.else
;Jesli serwer byl wlaczony to nacisniecie przycisku zamyka go i zrywa wszystkie
;polaczenie z klientami, po czym wyswietlana jest o tym informacja a tekst na
;przycisku zmienia sie spowrotem na Create server.
				invoke closesocket,hSock1
				mov		esi, offset acceptedSockets
				mov		edi, numberOfSockets
				.while edi!=0
					invoke closesocket,[esi]
					add		esi, 4
					dec		edi
				.endw
				invoke SetDlgItemText,hWin,btnCreateServer,addr createServer
				invoke AddToMainChat,addr serverStopped
				mov		isServerOn, 0
			.endif
		.elseif wParam==btnConnect
			.if isConnected==0
				mov		showmynick, 0
;Jesli nie jestesmy juz polaczeni z jakims serwerem to nacisniecie buttona
;Connect powoduje pobranie nicka z pola mynick.
				invoke GetDlgItemText,hWin,edtMyNick,addr myNick,64
				.if eax!=0
;Jesli pole nie bylo puste, to nastepuje pobranie IP z kontrolki IPAddress
;okreslonej jako Connect to, a nastepnie zmieniany jest napis na buttonie
;z Connect na Disconnect i wyswietlana jest informacja o nawiazywaniu polaczenia.
					invoke socket,PF_INET,SOCK_STREAM,IPPROTO_TCP
					mov		hSock2,eax
					invoke WSAAsyncSelect,eax,hWin,WM_SOCKET,FD_CONNECT or FD_READ or FD_WRITE or FD_CLOSE
					invoke htons,2323
					mov		SA2.sin_port,ax
					mov		SA2.sin_addr.S_un.S_addr,INADDR_ANY
					mov		SA2.sin_family,AF_INET
					invoke SendDlgItemMessage,hWin,ipaConnectTo,IPM_GETADDRESS,0,addr serverIP
					mov		eax, serverIP
					bswap	eax
					mov		SA2.sin_addr,eax
					invoke connect,hSock2,addr SA2,16
					invoke SetDlgItemText,hWin,btnConnect,addr sDisconnect
					invoke AddToMainChat,addr connecting
					mov		isConnected, 1
				.endif
			.else
;Jesli bylismy juz polaczeni z jakims serwerem, to jestesmy od niego rozlaczani
;i wyswietlana jest o tym informacja.
				invoke closesocket,hSock2
				invoke SetDlgItemText,hWin,btnConnect,addr sConnect
				invoke AddToMainChat,addr disconnected
				invoke SendDlgItemMessage,hWin,lstUsers,LB_RESETCONTENT,0,0
				mov		isConnected, 0
			.endif
		.elseif wParam==btnSend || wParam==1
;Jesli nacisnelismy button Send lub przycisk enter to wiadomosc z pola
;edycyjnego wysylana jest do serwera.
			invoke GetDlgItemText,hWin,edtToSend,addr editSend,1001
			invoke wsprintf,addr sendBuffer,addr textForm,addr editSend
			invoke SendToServer,addr sendBuffer
			invoke SetDlgItemText,hWin,edtToSend,addr zero
		.endif
	.elseif eax==WM_CLOSE
;WM_CLOSE - wiadomosc wysylana w przypadku klikniecia na przycisk [X].
;Zamykamy biblioteke winsock przy czym zrywane sa wszelkie aktywne polaczenia
;(o ile takie istnieja) i zamykamy okno dialogowe.
		invoke WSACleanup
		invoke EndDialog,hWin,0
	.elseif eax==WM_SOCKET
;WM_SOCKET - wszelkie komunikaty powiazane z komunikacja/nawiazywanie/zrywaniem
;polaczen sieciowych.
		mov		eax, wParam
		.if eax==hSock1 ;socket serwera do odbierania polaczen
			.if word ptr lParam==FD_ACCEPT
;FD_ACCEPT jest tu informacja dla serwera o nowym polaczeniu jakiegos klienta.
;Przygotowujemy socketa do komunikacji z danym klientem.
				invoke accept,hSock1,0,0
				.if numberOfSockets==50
;Jesli liczba polaczonych klientow jest rowna 50 to nie przyjmujemy
;juz nowego polaczenia.
					invoke closesocket,eax
				.else
					mov		ecx, numberOfSockets
					imul	ecx, ecx, 4
					add		ecx, offset acceptedSockets
					mov		[ecx], eax
					inc		numberOfSockets
					invoke WSAAsyncSelect,eax,hWin,54321,FD_CONNECT or FD_READ or FD_WRITE or FD_CLOSE
				.endif
			.endif
		.elseif eax==hSock2 ;socket klienta do laczenia z serwerem
			.if word ptr lParam==FD_CONNECT
;FD_CONNECT jest tu informacja dla klienta o pomyslnym polaczeniu z serwerem.
;Po nawiazaniu polaczenia klient wysyla do serwera swoj nick.
				invoke wsprintf,addr sendBuffer,addr nickForm,addr myNick
				invoke SendToServer,addr sendBuffer
			.elseif word ptr lParam==FD_CLOSE
;FD_CLOSE jest tu informacja dla klienta o tym, ze serwer zerwal polaczenie.
;Zamykanie socketa, informacja o rozlaczeniu i usuniecie wszystkich nickow
;z kontrolki listbox.
				invoke closesocket,hSock2
				invoke SetDlgItemText,hWin,btnConnect,addr sConnect
				invoke AddToMainChat,addr disconnected
				invoke SendDlgItemMessage,hWin,lstUsers,LB_RESETCONTENT,0,0
				mov		isConnected, 0
			.elseif word ptr lParam==FD_READ
;FD_READ jest tu informacja dla klienta o tym ze nadeszly jakies dane od serwera.
;Pobieramy otrzymane dane, deszyfrujemy je i przerabiamy otrzymane wiadomosci.
				invoke recv,hSock2,addr readBuffer,10*1024,0
				invoke Decrypt,addr readBuffer,eax
				invoke GetMsgNumber,addr readBuffer,eax
				mov		esi, eax
				.while esi!=0
					invoke GetOneMsgFromPos,addr oneMsg,addr readBuffer,esi
					mov		edi, offset oneMsg
					.if dword ptr [edi]==":txt"
;Wiadomosc ":txt" od serwera - zwykly tekst ktory jest wyswietlany.
						add		edi, 4
						invoke AddToMainChat,edi
					.elseif dword ptr [edi]==":ioj"
;Wiadomosc ":joi" od serwera - joins czyli informacja o polaczeniu do serwera
;nowego klienta. Wyswietlana jest ta informacja i do kontrolki listbox dodawany
;jest nowy element - nick osoby ktora polaczyla sie do serwera.
						add		edi, 4
						invoke AddToMainChat,edi
						add		edi, 7
						invoke SendDlgItemMessage,hWin,lstUsers,LB_ADDSTRING,0,edi
					.elseif dword ptr [edi]==":rap"
;Wiadomosc ":par" od serwera - parts czyli informacja o rozlaczeniu od serwera
;jakiegos klienta. Wyswietlana jest informacja i usuwany jest nick danej osoby
;z kontrolki listbox.
						add		edi, 4
						invoke AddToMainChat,edi
						add		edi, 7
						invoke SendDlgItemMessage,hWin,lstUsers,LB_FINDSTRING,-1,edi
						invoke SendDlgItemMessage,hWin,lstUsers,LB_DELETESTRING,eax,0
					.elseif dword ptr [edi]==":rsu"
;Wiadomosc :usr od serwera - user czyli informacja o tym kto juz jest polaczony
;z serwerem (wysylana do klienta po jego podlaczeniu jesli ktos inny juz jest
;polaczony z serwerem).
						add		edi, 4
						invoke lstrcmp,addr myNick,edi
						.if eax==0 && showmynick==0
							mov		showmynick, 1
						.else
							invoke SendDlgItemMessage,hWin,lstUsers,LB_ADDSTRING,0,edi
						.endif
					.endif
					dec		esi
				.endw
			.endif
		.endif
	.elseif eax==54321 ;sockety serwera do komunikacji z klientami (kazdy socket do innego klienta)
		.if word ptr lParam==FD_READ
;FD_READ jest tu informacja dla serwera o tym, ze nadeszly jakies nowe
;wiadomosci od klientow.
;Pobieramy te dane, deszyfrujemy je i przerabiamy.
			invoke recv,wParam,addr readBuffer,10*1024,0
			invoke Decrypt,addr readBuffer,eax
			mov		ecx,offset readBuffer
			.if dword ptr [ecx]==":cin"
;Wiadomosc ":nic" od klienta - nick czyli wiadomosc wysylana przez klienta do
;serwera po polaczeniu informujaca o tym jaki jest nick klienta.
;Po odebraniu tej wiadomosci serwer wysyla do wszystkich polaczonych klientow
;wiadomosc join o polaczeniu nowego klienta, a do klienta ktory wyslal wiadomosc
;nick wysyla wiadomosci user informujace o tym kto juz jest polaczony z serwerem.
				add		ecx, 4
				invoke GetNickFromSocket,wParam
				push	eax
				invoke lstrcpy,eax,ecx
				pop		eax
				invoke wsprintf,addr sendBuffer,addr joinsForm,eax
				invoke ServerSendToAll,addr sendBuffer
				mov		eax, numberOfSockets
				mov		ecx, offset acceptedNicks
				.while eax!=0
					pusha
					invoke wsprintf,addr sendBuffer,addr userForm,ecx
					inc		eax
					invoke Encrypt,addr sendBuffer,eax
					invoke send,wParam,addr sendBuffer,eax,0
					popa
					add		ecx, 64
					dec		eax
				.endw
			.elseif dword ptr [ecx]==":txt"
;Wiadomosc ":txt" od klienta - tekst otrzymany od klienta wysylany jest do
;wszystkich polaczonych z serwerem klientow.
				add		ecx, 4
				invoke GetNickFromSocket,wParam
				invoke wsprintf,addr sendBuffer,addr msgToShowForm,eax,ecx
				invoke ServerSendToAll,addr sendBuffer
			.endif
		.elseif word ptr lParam==FD_CLOSE
;FD_CLOSE jest tu informacja dla serwera o tym, ze dany klient zerwal polaczenie
;z serwerem. Serwer wysyla wiadomosc parts do polaczonych klientow.
			invoke GetNickFromSocket,wParam
			invoke wsprintf,addr sendBuffer,addr partsForm,eax
			invoke ServerSendToAll,addr sendBuffer
			invoke DeleteUser,wParam
		.endif
	.else
;Jesli nadeszla jakas wiadomosc, ktorej nie obslugiwalismy, to zwracamy false.
		mov		eax,FALSE
		ret
	.endif
;Zwracamy wartosc true jesli dana wiadomosc byla przez nas obslugiwana.
	mov		eax,TRUE
	ret

DlgProc endp

end start
