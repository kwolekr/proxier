/*-
 * Copyright (c) 2010 Ryan Kwolek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright notice, this list of
 *     conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *	proxier.c - 
 *     Injectable library that intercepts connect/WSAConnect calls to WS2_32 and wsock32 from
 *     an arbitrary module, preempting that connection with one to a proxy using the SOCKS4 
 *     protocol	if a connection is attempted to the specified addr/port.
 */


#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <winsock2.h>
#include <dbghelp.h>

#pragma comment(lib, "WS2_32.lib")
#pragma comment(lib, "DbgHelp.lib")

#define ARG_MODULENAME 1
#define ARG_DESTADDR   2
#define ARG_DESTPORT   3
#define ARG_PROXYADDR  4
#define	ARG_PROXYPORT  5


void LoadSettingsFromConfig(const char *cfgpath);
int InstallAPIHook(const char *modname, const char *fnname,
				   const char *targetmod, int newfn);
int RemoveAPIHook(const char *modname, const char *fnname,
				  const char *targetmod, int hookfn);
int ProcessHook(SOCKET s, const struct sockaddr *name, int namelen, int wsa, 
				LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
int WSAConnect_hook(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData,
					LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
int connect_hook(SOCKET s, const struct sockaddr *name, int namelen);
HMODULE LoadLibraryA_hook(LPCSTR lpLibFileName);
HMODULE LoadLibraryW_hook(LPCWSTR lpLibFileName);
void AddWinsockHooks();
void DispMsg(const char *fmt, ...);
DWORD WINAPI TextDrawProc(LPVOID lpParameter);


const char *failstrs[] = {
	"Request rejected or failed!",
	"Request rejected becasue SOCKS server cannot connect to identd on the client!",
	"Request rejected because the client program and identd report different user-ids!"
};

char basemodname[64];
char modname[64];

unsigned long tehaddr;
unsigned short tehport;

unsigned long proxyaddr;
unsigned short proxyport;

int cancel;
int drawnotify;
HANDLE hDrawEvent;
char texttodisp[256][8];
int numtext;
int revsem;


///////////////////////////////////////////////////////////////////////////////////////////////


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	WSADATA wsd;
	HANDLE hThread;
	int len, slept;
	char cfgpath[MAX_PATH];
	unsigned long tid;

	switch (fdwReason) {
		case DLL_PROCESS_ATTACH:

			DisableThreadLibraryCalls(hinstDLL);

			len = GetCurrentDirectory(sizeof(cfgpath), cfgpath);
			if (!len)
				return FALSE;

			strncpy(cfgpath + len, "\\proxier.ini", sizeof(cfgpath) - len);

			WSAStartup(0x0202, &wsd);

			hDrawEvent = CreateEvent(NULL, 0, 0, NULL);
			if (!hDrawEvent)
				return FALSE;

			hThread = CreateThread(NULL, 0, TextDrawProc, NULL, 0, &tid);
			if (!hThread)
				return FALSE;
			CloseHandle(hThread);

			DispMsg("proxier v1.0 loaded - enjoy");
		
			LoadSettingsFromConfig(cfgpath);

			if (!InstallAPIHook("kernel32.dll", "LoadLibraryA", basemodname, (int)LoadLibraryA_hook))
				DispMsg("Failed to install hook on kernel32!LoadLibraryA() in %s!", basemodname);
			if (!InstallAPIHook("kernel32.dll", "LoadLibraryW", basemodname, (int)LoadLibraryW_hook))
				DispMsg("Failed to install hook on kernel32!LoadLibraryA() in %s!", basemodname);

			break;
		case DLL_PROCESS_DETACH:

			if (GetModuleHandle(modname)) {
				RemoveAPIHook("WS2_32.DLL", "connect", modname, (int)connect_hook);
				RemoveAPIHook("WS2_32.DLL", "WSAConnect", modname, (int)WSAConnect_hook);
				RemoveAPIHook("wsock32.dll", "connect", modname, (int)connect_hook);
				RemoveAPIHook("wsock32.dll", "WSAConnect", modname, (int)WSAConnect_hook);
			}

			if (!InstallAPIHook("kernel32.dll", "LoadLibraryA", basemodname, (int)LoadLibraryA_hook))
				DispMsg("Failed to install hook on kernel32!LoadLibraryA() in %s!", basemodname);
			if (!InstallAPIHook("kernel32.dll", "LoadLibraryW", basemodname, (int)LoadLibraryW_hook))
				DispMsg("Failed to install hook on kernel32!LoadLibraryA() in %s!", basemodname);
			
			slept = 0;
			while (revsem && (slept < 30000)) {
				Sleep(50);
				slept += 50;
			}

			cancel = 1;
			SetEvent(hDrawEvent);
	}
	return TRUE;
}


void LoadSettingsFromConfig(const char *cfgpath) {
	char buf[256];

	GetPrivateProfileString("proxier", "basemodname", "Game.exe", basemodname, sizeof(modname), cfgpath);
	GetPrivateProfileString("proxier", "modname", "d2client.dll", modname, sizeof(modname), cfgpath);
	GetPrivateProfileString("proxier", "tehaddr", "66.225.232.178", buf, sizeof(buf), cfgpath);
	tehaddr = inet_addr(buf);
	GetPrivateProfileString("proxier", "tehport", "6112", buf, sizeof(buf), cfgpath);
	tehport = atoi(buf);
	GetPrivateProfileString("proxier", "proxyaddr", "127.0.0.1", buf, sizeof(buf), cfgpath);
	proxyaddr = inet_addr(buf);
	GetPrivateProfileString("proxier", "proxyport", "1080", buf, sizeof(buf), cfgpath);
	proxyport = atoi(buf);
	GetPrivateProfileString("proxier", "drawnotify", "1", buf, sizeof(buf), cfgpath);
	drawnotify = atoi(buf);
}


void DispMsg(const char *fmt, ...) {
	char buf[256];
	va_list val;

	va_start(val, fmt);
	vsprintf(buf, fmt, val);

	if (drawnotify) {
		strncpy(texttodisp[numtext], buf, 256);
		numtext++;
		if (numtext == 16)
			numtext = 0;
		SetEvent(hDrawEvent);
	} else {
		MessageBox(0, buf, "Proxier", 0);
	}

	va_end(val);
}


DWORD WINAPI TextDrawProc(LPVOID lpParameter) {
	int cycles, i, event;
	HDC hdc;
	HGDIOBJ hOld;
	RECT rc;
	
	rc.left   = 0;
	rc.top    = 0;
	rc.right  = 0x180;
	rc.bottom = 0x100;

	hdc  = GetDC(NULL);
	hOld = SelectObject(hdc, GetStockObject(DEFAULT_GUI_FONT));

	while (1) {

		WaitForSingleObject(hDrawEvent, INFINITE);
		cycles = 7500 / 250;

		while (cycles) {
			
			for (i = 0; i != numtext + 1; i++) {	
				DrawText(hdc, texttodisp[i], -1, &rc, DT_NOCLIP);
				rc.top += 12;
			}
			rc.top = 0;

			event = WaitForSingleObject(hDrawEvent, 250);
			if (!event) {
				if (cancel)
					goto finished;
				else 
					cycles = 7500 / 250;
			}
			cycles--;
		}

		numtext = 0;
	}

finished:
	SelectObject(hdc, hOld);
	ReleaseDC(NULL, hdc);
	return 0;
}


///////////////////////////////////////////////////////////////////////////////


int InstallAPIHook(const char *modname, const char *fnname,
				   const char *targetmod, int newfn) {
	int len, i, *blah, lookingfor;
	unsigned long oldprotect;

	HANDLE hModule = GetModuleHandle(targetmod);
	if (!hModule) {
		DispMsg("Failed to get base of %s!", targetmod);
		return 0;
	}

	blah = (int *)ImageDirectoryEntryToData((void *)hModule,
		1, IMAGE_DIRECTORY_ENTRY_IAT, (unsigned long *)&len);
	lookingfor = (int)GetProcAddress(GetModuleHandle(modname), fnname);

	for (i = 0; i != len; i++) {
		if (lookingfor == blah[i])
			goto success;
	}

	DispMsg("Failed to find %s in IAT of %s!", fnname, modname);
	return 0;

success:
	VirtualProtect(&blah[i], sizeof(int), PAGE_EXECUTE_READWRITE, &oldprotect);
	blah[i] = newfn;
	VirtualProtect(&blah[i], sizeof(int), oldprotect, &oldprotect);
	return 1;
}


int RemoveAPIHook(const char *modname, const char *fnname,
				  const char *targetmod, int hookfn) {
	int len, i, *blah;
	unsigned long oldprotect;

	HANDLE hModule = GetModuleHandle(targetmod);
	if (!hModule) {
		DispMsg("Failed to get base of %s!", targetmod);
		return 0;
	}

	blah = (int *)ImageDirectoryEntryToData((void *)hModule,
		1, IMAGE_DIRECTORY_ENTRY_IAT, (unsigned long *)&len);

	for (i = 0; i != len >> 2; i++) {
		if (hookfn == blah[i])
			goto success;
	}

	DispMsg("Failed to find %s in IAT of %s!", fnname, modname);
	return 0;

success:
	VirtualProtect(&blah[i], sizeof(int), PAGE_EXECUTE_READWRITE, &oldprotect);
	blah[i] = (int)GetProcAddress(GetModuleHandle(modname), fnname);
	VirtualProtect(&blah[i], sizeof(int), oldprotect, &oldprotect);
	return 1;
}			


int ProcessHook(SOCKET s, const struct sockaddr *name, int namelen, int wsa, 
				LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
	struct sockaddr_in *sa, proxyname;
	char sendbuf[32], recvbuf[32];
	int recvlen;

	sa = (struct sockaddr_in *)name;
	if ((sa->sin_addr.s_addr == tehaddr) && (sa->sin_port == tehport)) {

		DispMsg("You're trying to connect to %s:%u, now proxizing...",
			inet_ntoa(sa->sin_addr), htons(sa->sin_port));
		
		memset(&proxyname, 0, sizeof(proxyname));
		proxyname.sin_family = AF_INET;
		proxyname.sin_addr.s_addr = proxyaddr;
		proxyname.sin_port = htons(proxyport);

		if (connect(s, (const struct sockaddr *)&proxyname, sizeof(struct sockaddr_in)) == SOCKET_ERROR) {
			DispMsg("Connection to %s:%u failed, error %d!",
				proxyaddr, proxyport, WSAGetLastError());
			return 0;
		}
		
		memcpy(sendbuf, "\x04\x01\xFF\xFF\xFF\xFF\xFF\xFF""anonymous\x00", 18);
		*(unsigned short *)(sendbuf + 2) = htons(tehport);
		*(unsigned long *) (sendbuf + 4) = tehaddr;

		send(s, sendbuf, 18, 0);

		recvlen = recv(s, recvbuf, sizeof(recvbuf), 0);
		if (!recvlen || recvlen == SOCKET_ERROR) {
			DispMsg("recv() failed, error %d!", WSAGetLastError());
			WSASetLastError(10053);
			return SOCKET_ERROR;
		}
		if (*recvbuf != 0) {
			DispMsg("SOCKS version not 0 as expected!");
			WSASetLastError(10053);
			return SOCKET_ERROR;
		}
		switch (recvbuf[1]) {
			case 90:
				DispMsg("Proxy request granted.");
				break;
			case 91:
			case 92:
			case 93:
				DispMsg(failstrs[recvbuf[1] - 91]);
				WSASetLastError(10053);
				return SOCKET_ERROR;
		}
		return 0;
	} else {
		if (wsa)
			return WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
		else
			return connect(s, name, namelen);
	}
}


int WSAConnect_hook(SOCKET s, const struct sockaddr *name, int namelen, LPWSABUF lpCallerData,
					LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
	revsem++;
	return ProcessHook(s, name, namelen, 1, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	revsem--;
}


int connect_hook(SOCKET s, const struct sockaddr *name, int namelen) {
	revsem++;
	return ProcessHook(s, name, namelen, 0, NULL, NULL, NULL, NULL);
	revsem--;
}


HMODULE LoadLibraryA_hook(LPCSTR lpLibFileName) {
	if (!_stricmp(lpLibFileName, modname) && !GetModuleHandleA(lpLibFileName))
		AddWinsockHooks();
	return LoadLibraryA(lpLibFileName);
}


HMODULE LoadLibraryW_hook(LPCWSTR lpLibFileName) {
	WCHAR wmodname[64];

	MultiByteToWideChar(CP_ACP, 0, modname, -1, wmodname, sizeof(wmodname) / sizeof(WCHAR));

	if (!_wcsicmp(lpLibFileName, wmodname) && !GetModuleHandleW(lpLibFileName))
		AddWinsockHooks();
	return LoadLibraryW(lpLibFileName);
}


void AddWinsockHooks() {
	if (!InstallAPIHook("WS2_32.DLL", "connect", modname, (int)connect_hook))
		DispMsg("Failed to install hook on WS2_32!connect() in %s!", modname);
	if (!InstallAPIHook("WS2_32.DLL", "WSAConnect", modname, (int)WSAConnect_hook))
		DispMsg("Failed to install hook on WS2_32!WSAConnect() in %s!", modname);
	if (!InstallAPIHook("wsock32.dll", "connect", modname, (int)connect_hook))
		DispMsg("Failed to install hook on wsock32!connect() in %s!", modname);
	if (!InstallAPIHook("wsock32.dll", "WSAConnect", modname, (int)WSAConnect_hook))
		DispMsg("Failed to install hook on wsock32!WSAConnect() in %s!", modname);
}

