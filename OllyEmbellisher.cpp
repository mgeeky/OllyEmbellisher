// OllyEmbellisher.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <iostream>
#include "OllyEmbellisher.h"
#include <tlhelp32.h>

#pragma warning(disable:4996)


////////////////////////////////////////////////////////////////////////

HINSTANCE   g_hInstance;
HWND        g_hOllyWnd, g_hOptionsWnd;
char		g_szPluginClassName[ 32];
bool		g_bEscapeClosesChild = false;
DWORD		g_dwTemporary = (DWORD)-1;			// Used in EIP Modification
DWORD		g_dwPreviousEIP = (DWORD)-1;
HHOOK		g_hGetMessageHook;
DWORD		g_hOllyProcessID;
DWORD		*g_dwHandleOfCommentsArray;
DWORD		g_dwNumberOfCommentsInArray;


////////////////////////////////////////////////////////////////////////


BOOL APIENTRY 	DllMain 			(HINSTANCE, DWORD, LPVOID );
void			Message				( const char *szFormat, ...);

BOOL CALLBACK	OptionsDlgProcedure	(HWND hw,UINT msg,WPARAM wp,LPARAM lp);
BOOL CALLBACK	ModifyEIPProcedure	(HWND hw,UINT msg,WPARAM wp,LPARAM lp);

void LogToFile( char *szData, ...);

void				PatchOlly			();

#ifdef USE_MARK_ENTRYPOINTS
void				MarkProceduresEntryPoints	( );
#endif

extc int  _export cdecl ODBG_Plugininit	(int ollydbgversion, HWND hw, ulong *features);
extc void _export	ODBG_Plugindestroy	(void);
extc int _export 	ODBG_Plugindata		(char szShortName[32]);
extc int _export	ODBG_Pluginmenu		(int origin,char data[4096],void *item);
extc void _export	ODBG_Pluginaction	(int origin,int action,void *item);
extc void _export	ODBG_Pluginreset	(void);
extc int _export	ODBG_Pluginclose	(void);
extc int _export	ODBG_Pluginshortcut (int origin,int ctrl,int alt,int shift,int key,void *item);
//extc void _export	ODBG_Plugindestroy	(void);
extc void _export	ODBG_Pluginreset	(void);

#ifdef USE_DETACHING_CODE
LRESULT CALLBACK	GetMessageHookProc	( int code, WPARAM wParam, LPARAM lParam );
#endif


////////////////////////////////////////////////////////////////////////

BOOL APIENTRY DllMain (HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved )
{
    if( dwReason == DLL_PROCESS_ATTACH)
        g_hInstance = hInst;

    return TRUE;
}


////////////////////////////////////////////////////////////////////////

void Message( const char *szFormat, ...)
{
	va_list	va;
	_crt_va_start( va, szFormat);

	char	szTxt[ 512] = "";
	vsnprintf( szTxt, sizeof szTxt, szFormat, va);
	_crt_va_end( va);
	
	MessageBoxA( NULL, szTxt, "Message", MB_ICONINFORMATION) ;
}


////////////////////////////////////////////////////////////////////////

extc int _export ODBG_Plugininit (int iOllyDbgVersion, HWND hOllyWnd, ulong *ulReserved )
{
    g_hOllyWnd = hOllyWnd;

	if( iOllyDbgVersion < PLUGIN_VERSION ) return -1;

	//if( Registerpluginclass( g_szPluginClassName, NULL, g_hInstance, MDIWindowProcedure ) < 0)
	//	return -1;

	_Addtolist( 0, 0, "OllyEmbellisher plugin has been Initialized !");
	_Addtolist( 0, -1,"      ...from MGeeky's (C) bench, 2010");

	g_bEscapeClosesChild = (bool)_Pluginreadintfromini( g_hInstance, STR_ESC_CLOSES_CHILD, 0);

	HMENU hViewMenu = GetSubMenu( GetMenu( g_hOllyWnd), 1);
	MENUITEMINFOA	miInfo;
	miInfo.cbSize = sizeof miInfo;
	miInfo.fMask = MIIM_TYPE;
	miInfo.fType = MFT_STRING;
	miInfo.dwTypeData = "Threads\tAlt+T";
	miInfo.cch = strlen("Threads\tAlt+T");
	SetMenuItemInfoA( hViewMenu, 4, TRUE, &miInfo);

	GetWindowThreadProcessId( g_hOllyWnd, &g_hOllyProcessID);
	DWORD dwOllyID = g_hOllyProcessID;

	PatchOlly();	

#ifdef USE_DETACHING_CODE
	HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
	if( hSnap != (HANDLE)-1)
	{
		THREADENTRY32 teThread;
		teThread.dwSize = sizeof teThread;

		if( Thread32First( hSnap, &teThread) )
		{
			while( teThread.th32OwnerProcessID != dwOllyID )
				Thread32Next( hSnap, &teThread);

			g_hGetMessageHook = SetWindowsHookExA( WH_GETMESSAGE, GetMessageHookProc, g_hInstance, 
												teThread.th32ThreadID );
			if( g_hGetMessageHook == 0)
			{
				char szError[ 256] = "";
				sprintf( szError, "Cannot create global hook for OllyDbg application! (%d)", GetLastError() );
				_Addtolist( 0, 1, szError );
			}else
				_Addtolist( 0, 0, "OllyEmbellisher has successfully created hook for Olly's first thread: %d"
								" (found Olly's process ID: %d)", teThread.th32ThreadID, 
								dwOllyID );
		}
		CloseHandle( hSnap);
	}
#endif
	
	return 0;
}

////////////////////////////////////////////////////////////////////////

extc void _export ODBG_Plugindestroy	(void)
{
#ifdef USE_DETACHING_CODE
	if( g_hGetMessageHook )
		UnhookWindowsHookEx( g_hGetMessageHook);
#endif
}

////////////////////////////////////////////////////////////////////////

extc int _export ODBG_Plugindata(char szShortName[32])
{
	sprintf( szShortName, "OllyEmbellisher");
	return PLUGIN_VERSION;
}


////////////////////////////////////////////////////////////////////////

BOOL CALLBACK ModifyEIPProcedure(HWND hw,UINT msg,WPARAM wParam, LPARAM lp)
{
	if( msg == WM_INITDIALOG)
	{
		SetFocus( GetWindow( hw, IDC_NEW_EIP) );
		RECT rc;
		GetWindowRect( GetWindow( hw, IDC_NEW_EIP), &rc);
		SendMessageA( GetWindow( hw, IDC_NEW_EIP), EM_LIMITTEXT, (WPARAM)127, 0);

		POINT pt = { rc.left, rc.top };
		ScreenToClient( GetWindow( hw, IDC_NEW_EIP), &pt); 
		SendMessageA( hw, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(pt.x+6, pt.y+3 ) );

		char szEIP[ 10] = "";
		sprintf( szEIP, "%08X", (DWORD)((t_thread*)_Findthread( _Getcputhreadid() ))->reg.ip);
		SetDlgItemTextA( hw, IDC_NEW_EIP, szEIP);

		if( g_dwPreviousEIP != (DWORD)-1 ){
			char szInfo[ 64] = "";
			sprintf( szInfo, "Previous EIP value:  %08X", g_dwPreviousEIP);
			SetDlgItemTextA( hw, IDC_INFO, szInfo);
			ShowWindow( GetDlgItem( hw, IDC_PUT_PREVIOUS_EIP), SW_SHOW);
		}
	}
	else if( msg == WM_COMMAND)
	{
		if( LOWORD( wParam) == IDOK)
		{
			char	szValue[256];
			DWORD	dwAddress = (DWORD)-1;
			bool	bName = false;

			GetDlgItemTextA( hw, IDC_NEW_EIP, szValue, sizeof szValue - 1);

			for( unsigned u = 0; u < strlen( szValue); u++)
				if( isalpha( szValue[u]) && tolower( szValue[u]) > 'f' )
				{	bName = true; break; }

			if( bName )
			{
				if( 0 == strcmp( szValue, "ModuleEntryPoint") )
					strcpy( szValue, "<ModuleEntryPoint>");
				if( _Findlabelbyname( szValue, &dwAddress, 0, 0xFFFFFFFF) == NM_NONAME )
				{	
					SetDlgItemTextA( hw, IDC_INFO, "Unknown identifier !");	
					return 0;	
				}
			}else dwAddress = strtol( szValue, NULL, 16);

			g_dwTemporary = dwAddress;
			EndDialog( hw, 0);
		}else if( LOWORD(wParam) == IDCANCEL)
			EndDialog( hw, -1);
		else if( LOWORD(wParam) == IDC_RESTORE_ORIGIN)
		{
			_Sendshortcut(PM_DISASM,0,WM_CHAR,0,0,'*');
			
			char szValue[ 10] = "";
			sprintf( szValue, "%08X", (DWORD)((t_dump*)_Plugingetvalue( VAL_CPUDASM))->addr );
			SetDlgItemTextA( hw, IDC_NEW_EIP, szValue);

		}else if( LOWORD(wParam) == IDC_PUT_PREVIOUS_EIP)
		{
			char szValue[ 64] = "";
			GetDlgItemTextA( hw, IDC_INFO, szValue, sizeof szValue - 1);

			if( strlen( szValue) == 0 || NULL == strstr( szValue, "Previous EIP value")) 
				return 0;
			SetDlgItemTextA( hw, IDC_NEW_EIP, &szValue[ strlen( szValue)-8]);
		}
	}else if( msg == WM_CLOSE || msg == WM_QUIT || msg == WM_DESTROY )
		EndDialog( hw, -1);

	return 0;
}


////////////////////////////////////////////////////////////////////////

BOOL CALLBACK OptionsDlgProcedure(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static bool b1, b2;

	switch( msg)
	{
	case WM_INITDIALOG:
		{
			b1 = (bool)(_Pluginreadintfromini( g_hInstance, STR_CLEAN_DISASM_POPUP, 0)!=0);
			b2 = (bool)(_Pluginreadintfromini( g_hInstance, STR_ESC_CLOSES_CHILD, 0)!=0);

			CheckDlgButton( hwnd, IDC_CLEAN_DISASM_MENU, b1);
			CheckDlgButton( hwnd, IDC_ESC_CLOSES_CHILD, b2 );

			b1 = (bool)(_Pluginreadintfromini( g_hInstance, STR_ALLOW_EIP_MODIFICATION, 0)!=0);
			CheckDlgButton( hwnd, IDC_ALLOW_EIP_MODIFICATION, b1);
#ifdef USE_DETACHING_CODE
			b1 = (bool)(_Pluginreadintfromini( g_hInstance, STR_REPLACE_DETACH, 0)!=0);
			CheckDlgButton( hwnd, IDC_REPLACE_DETACH, b1);
#else
			ShowWindow( GetDlgItem( hwnd, IDC_REPLACE_DETACH), SW_HIDE);
#endif
		}
		break;

	case WM_COMMAND:
		{
#define ISCHECKED( ID)	((IsDlgButtonChecked( hwnd, ID)))
#define CHECK(ID)		else if( LOWORD( wParam) == ID ){CheckDlgButton( hwnd, ID, \
							IsDlgButtonChecked( hwnd, ID));}

			if( LOWORD( wParam) == IDOK)
			{
				_Pluginwriteinttoini( g_hInstance, STR_CLEAN_DISASM_POPUP, 
									ISCHECKED(IDC_CLEAN_DISASM_MENU) );
				_Pluginwriteinttoini( g_hInstance, STR_ESC_CLOSES_CHILD, ISCHECKED(IDC_ESC_CLOSES_CHILD) );
				_Pluginwriteinttoini( g_hInstance, STR_ALLOW_EIP_MODIFICATION, 
									ISCHECKED( IDC_ALLOW_EIP_MODIFICATION));
#ifdef USE_MARK_ENTRYPOINTS
				_Pluginwriteinttoini( g_hInstance, STR_MARK_PROCEDURES_EPES, 
									ISCHECKED( IDC_MARK_PROCEDURES_ENTRYPOINTS) );
#endif
#ifdef USE_DETACHING_CODE
				_Pluginwriteinttoini( g_hInstance, STR_REPLACE_DETACH, ISCHECKED(IDC_REPLACE_DETACH) );
#endif


				// Change "Op&tions" to "Opt&ions" to make possible register ALT-T shortcut
				// for invoking Threads Window
				/*{
					bool bSet = false;
					if( (bool)ISCHECKED(IDC_ESC_CLOSES_CHILD))
						bSet = true;

					WCHAR wModuleName[ 256] = { L"" };
					GetModuleFileName( g_hInstance, wModuleName, 256);
					char szModuleName[ 256] = "";
					if( WideCharToMultiByte( CP_ACP, WC_DISCARDNS, (LPCWSTR)wModuleName, -1, szModuleName, 
											256, NULL, NULL))
					{
						HANDLE hFile = CreateFileA( szModuleName, GENERIC_WRITE, 
													FILE_SHARE_READ|FILE_SHARE_WRITE, 
													NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
						if( hFile != (HANDLE)-1 && !GetLastError() )
						{
							// "Op&tions" -> "Opt&ions"
							DWORD dwWritten = 0;
							unsigned char lpBuff[3] = { ((bSet)? 0x74 : 0x26), 0x00, 
														((bSet)? 0x26 : 0x74) };
							WriteFile( hFile, (LPCVOID)lpBuff, 3, &dwWritten, NULL);
							CloseHandle( hFile);
						}
					}
				}*/

				if( ISCHECKED(IDC_CLEAN_DISASM_MENU) || ISCHECKED(IDC_ESC_CLOSES_CHILD) )
					MessageBoxA(NULL, "Some changes needs to restart Olly's application.", 
								"Info", 0);

				EndDialog(hwnd, 0);

			}else if( LOWORD( wParam) == IDCANCEL)
				EndDialog(hwnd, 0);
			
			CHECK(IDC_CLEAN_DISASM_MENU)
			CHECK(IDC_ESC_CLOSES_CHILD)
			CHECK(IDC_ALLOW_EIP_MODIFICATION)
#ifdef USE_DETACHING_CODE
			CHECK(IDC_REPLACE_DETACH )
#endif
#ifdef USE_MARK_ENTRYPOINTS
			CHECK(IDC_MARK_PROCEDURES_ENTRYPOINTS )
			
			if( _Getstatus() != STAT_NONE )
				MarkProceduresEntryPoints();
#endif
			
		}
		break;

	case WM_CLOSE:
	case WM_QUIT:
	case WM_DESTROY:
		{
			EndDialog( hwnd, 0);
		}
		break;

	default:	return FALSE;
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////

extc int _export ODBG_Pluginmenu(int iOrigin, char data[4096], void *item)
{
	if( iOrigin == PM_MAIN )
	{
		strcpy( data, "0 &Options|1 &About..." );
		return 1;
	}
	else if( iOrigin == PM_CPUREGS /*&& ((t_reg*)item)->selected & RS_EIP == REG_EIP */ )
	{
		if(_Pluginreadintfromini(g_hInstance, STR_ALLOW_EIP_MODIFICATION, 0) != 0)
		{
			strcpy( data, "61 Modify EIP");
			return 1;
		}
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////

extc void _export ODBG_Pluginaction (int iOrigin, int iAction, void *item)
{
	if( iOrigin == PM_MAIN)
	{
		switch( iAction)
		{
		case 0:
			{
				// "Options" position from main menu
				DialogBoxA( g_hInstance, (LPSTR)IDD_DIALOG1, g_hOllyWnd, OptionsDlgProcedure);
			}
			break;

		case 1:
			{
				// "About" position from main menu
				char szInfo[ 512] = "";

				sprintf( szInfo,	"OllyEmbellisher plugin - v%s, MGeeky (C) 2010\n"
									"\nSimple plugin that cleans some OllyDbg interface,"
									" by for example: deleting superfluous positions in"
									" GUI popup menus.", 
									OLLYEMBELLISHER_VERSION );
				MessageBoxA( g_hOllyWnd, szInfo, "OllyEmbellisher about", MB_OK|MB_ICONINFORMATION);
			}
			break;
		default: break;
		}
	}else if( iOrigin == PM_CPUREGS )
	{
		if( iAction == 61)
		{
			t_thread *tThread = _Findthread( _Getcputhreadid() );
			if( tThread == NULL ) return;

			g_dwTemporary = (DWORD)-1;
			g_dwPreviousEIP = tThread->oldreg.ip;

			DialogBoxA( g_hInstance, (LPCSTR)IDD_DIALOG2, g_hOllyWnd, ModifyEIPProcedure);

			// Backup of current registry contents
			if( /* tThread->reg.modifiedbyuser == 0 && */ g_dwTemporary != (DWORD)-1)
			{
				tThread->oldreg = tThread->reg;
				tThread->reg.ip = tThread->context.Eip = g_dwTemporary;
				tThread->reg.modified = 1;
				tThread->reg.modifiedbyuser = 1;

				_Broadcast( WM_USER_CHREG, 0, 0);
				_Setcpu( tThread->threadid, g_dwTemporary, 0, 0, 
						CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS|CPU_REDRAW);
				_Redrawdisassembler();
				//_Infoline( "EIP of thread %X (%d.) has been successfully changed ( 0x%X -> 0x%X )", 
				//		tThread->threadid, tThread->threadid, tThread->oldreg.ip, tThread->reg.ip );
			}
		}
	}
}


////////////////////////////////////////////////////////////////////////

extc int _export ODBG_Pluginclose(void) 
{
	__asm{
		nop
	}
	return 0;
};

////////////////////////////////////////////////////////////////////////

void LogToFile( char *szData, ...)
{
	static bool bFirstTime = true;
	FILE *pFile = fopen( "C:\\Users\\Mariusz\\Desktop\\OllyEmbellisher_LOG.txt", 
						(bFirstTime)? "wb" : "ab");
	if( pFile)
	{
		char *szText = (char*)malloc( strlen( szData) * 12+1);
		memset( szText, 0, strlen( szData) * 12+1);

		va_list va;
		_crt_va_start( va, szData);
		vsnprintf( szText, strlen( szData) * 12, szData, va);
		_crt_va_end( va);

		fwrite( (const void*)szText, 1, strlen( szText)+1, pFile);
		free( szText);
		fclose( pFile);
	}
	bFirstTime = false;
}


////////////////////////////////////////////////////////////////////////

extc int _export ODBG_Pluginshortcut (int origin,int ctrl,int alt,int shift,int key,void *item)
{

	// WARNING !
	// WinDBG notes that CTRL_W sets "key" parameter to 0x87 (VK_F24) instead of 57h (VK_W)
	if( ctrl == 0 && alt == 1 && key == 0x54 /* VK_T */) _Createthreadwindow();
	if( (ctrl == 0 && alt == 0 && shift == 0 && key == VK_ESCAPE && g_bEscapeClosesChild)
		|| ( ctrl == 1 && alt == 0 && shift == 0 && key == VK_F24 /*(int)'w'*/ && g_bEscapeClosesChild ) )
	{
		switch( origin)
		{
		case PM_MODULES: DestroyWindow( ((t_module*)item)->namelist.hw ); break;
		case PM_WINDOWS: DestroyWindow( (HWND)((t_window*)item)->hwnd ); break;
		case PM_MEMORY:
		case PM_BREAKPOINTS:
		case PM_REFERENCES:
		case PM_THREADS:
		case PM_RTRACE:
		case PM_WATCHES:
			_Sendshortcut( PM_MAIN, 0, WM_KEYDOWN, VK_F4, 1, 0 );
			break;

		case PM_CPUSTACK:
			_Sendshortcut( PM_CPUSTACK, 0, WM_KEYDOWN, VK_F4, 1, 0 );
			break;
		}
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////

void PatchOlly()
{

	// Applying code patches, raw to the internal memory of Olly's process.
	if( _Pluginreadintfromini( g_hInstance, STR_CLEAN_DISASM_POPUP, 0) != 0)
	{
		HANDLE hOllyProcess = OpenProcess( PROCESS_VM_WRITE|PROCESS_VM_OPERATION, 
											FALSE, g_hOllyProcessID);
		if( hOllyProcess == (HANDLE)-1)
		{
			char szErr[ 64] = "";
			sprintf( szErr, "OpenProcess: %d, id: %d", GetLastError(), g_hOllyProcessID);
			MessageBoxA( 0, szErr, "", 0);
			return;
		}

		// Patching process code
		DWORD	dwWritten,
				//					Assemble    Label        Comment    Follow     Help on Sym. Name
				dwAddresses[ ] = { 0x00420CD7, 0x00420D0B, 0x00420D3F, 0x0042133D, 0x00422C0E	};

		char	szPatch[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

		for( unsigned u = 0; u < sizeof dwAddresses / sizeof DWORD; u++)
		{
			WriteProcessMemory( hOllyProcess, (LPVOID)dwAddresses[u], szPatch, 5, &dwWritten);
		}

		CloseHandle( hOllyProcess);
	}

}


////////////////////////////////////////////////////////////////////////

extc void _export ODBG_Pluginreset( void )
{
	// Process is probably reached by Attaching
	
#ifdef USE_DETACHING_CODE
	if( _Pluginreadintfromini( g_hInstance, STR_REPLACE_DETACH, 0) != 0)
	{
		HMENU hMenu		= GetMenu( g_hOllyWnd );
		HMENU hFileMenu = GetSubMenu( hMenu, 0);

		MENUITEMINFOA	miMenuInfo;
		memset( &miMenuInfo, 0, sizeof miMenuInfo);
		miMenuInfo.cbSize = sizeof miMenuInfo;
		miMenuInfo.fMask = MIIM_ID | MIIM_TYPE;
		miMenuInfo.fType = MFT_STRING;
		miMenuInfo.wID = DETACH_DEBUGGER_MENUITEM;
		miMenuInfo.dwTypeData = "Detach from Debugger";
		miMenuInfo.cch = strlen( miMenuInfo.dwTypeData );

		if( !InsertMenuItemA( hFileMenu, 2003, FALSE, &miMenuInfo ))
		{
			char szInfo[ 256] = "";
			sprintf( szInfo, "Error while inserting menu item ! (%d), hMenu: %d, hFileMenu: %d", 
				GetLastError(), hMenu, hFileMenu );
			MessageBoxA( 0, szInfo, "Inserted menu item error", MB_ICONERROR);
		}
	}
#endif
#ifdef USE_MARK_ENTRYPOINTS
	if( _Pluginreadintfromini( g_hInstance, STR_MARK_PROCEDURES_EPES, 0) )
	{
		MarkProceduresEntryPoints();
	}
#endif 

	// Recognizing UnhandledExceptionFilter default procedure (creating a label)
	/*{
		Message( "Recognizing UnhandledExceptionFilter default procedure (creating a label)" );

		DWORD	dwProcID = _Plugingetvalue( VAL_PROCESSID);
		DWORD	aAddresses[2] = { 0, 0 };
		HANDLE	hThread = (HANDLE)-1;

		DWORD (__stdcall *pNTQSI)( DWORD, PVOID, DWORD, LPDWORD) = 
			(DWORD (__stdcall *)( DWORD, PVOID, DWORD, LPDWORD))
				GetProcAddress( GetModuleHandleA( "NTDLL.DLL"), "NtQuerySystemInformation");
		DWORD	dwLen = 0;
		SYSTEM_HANDLE_INFORMATION	*shiHandles = (SYSTEM_HANDLE_INFORMATION*)malloc( 10);
		pNTQSI( 16, shiHandles, 9, &dwLen);

		free( (void*)shiHandles);

		shiHandles = (SYSTEM_HANDLE_INFORMATION*)malloc( dwLen + 1);
		memset( shiHandles, 0, dwLen + 1);

		pNTQSI( 16, shiHandles, dwLen, &dwLen);		// SystemHandleInformation

		for( unsigned u = 0; u < shiHandles->HandleCount; u++)
		{
			if( shiHandles->Handles->OwnerPid == dwProcID )
				if( shiHandles->Handles->ObjectType == 6 )	// Thread
				{
					// Process have only one Thread handle, because it posses only one
					// active thread.
					hThread = (HANDLE)shiHandles->Handles->HandleValue;
					Message( "hThread = %.8X; dwProcID = %X; u = %d;", hThread, dwProcID, u );VAL_
					break;
				}
		}

		free( (void*)shiHandles);
				
		CONTEXT	ctx;
		GetThreadContext( hThread, &ctx);

		Message( "ctx.SegFS = %.8X;", ctx.SegFs );

		DWORD dwSEHChainTop = 0;
		_Readmemory( (void*)&dwSEHChainTop, ctx.SegFs, 4, MM_SILENT );	// Reading SEH Chain Top
		_Readmemory( (void*)aAddresses, dwSEHChainTop, 8, MM_SILENT );	// Reading _EXCEPTION_REGISTRATION

		// Creating a label with _EXCEPTION_REGISTRATION_RECORD->Handler
		_Quickinsertname( aAddresses[ 1], NM_LABEL, "<UnhandledExceptionFilter>");

	}*/
}


////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK GetMessageHookProc	( int code, WPARAM wParam, LPARAM lParam )
{
	if( code < 0) return CallNextHookEx( g_hGetMessageHook, code, wParam, lParam);

	MSG	*pMsg = (MSG*)lParam;

	if( pMsg->message == WM_COMMAND )
	{
#ifdef USE_DETACHING_CODE
		if( LOWORD( pMsg->wParam ) == DETACH_DEBUGGER_MENUITEM )
		{
			if( !DebugActiveProcessStop( _Plugingetvalue( VAL_PROCESSID) ))
			{
				char szInfo[ 256];
				sprintf( szInfo, "An error has occured while Detaching process from debugger ! (%d)",
						GetLastError() );
				MessageBoxA(0, szInfo, "Error while Detaching", MB_ICONERROR);
			}
		}
#endif
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////
#ifdef USE_MARK_ENTRYPOINTS 
DWORD WINAPI _MarkProceduresEntryPoints	( LPVOID lParam )
{
	// WinDBG notes that this instruction does not working
	/*bool bSearchForLabels = ((g_dwHandleOfCommentsArray == 0)? FALSE : TRUE);*/

	static bool bSearchForLabels = true;
	char szName[ 256] = "";

	if( bSearchForLabels )
	{
		g_dwHandleOfCommentsArray = (DWORD*)malloc( MAX_NUMBER_OF_MARKED_LABELS*4);
		memset( (void*)g_dwHandleOfCommentsArray, 0, MAX_NUMBER_OF_MARKED_LABELS*4 );
		bSearchForLabels = false;
	
		int iType = _Findlabel( 0, szName);
		if( iType != NM_NONAME) goto _N;

		for( DWORD dwAddr = 0; dwAddr < 0xFFFFFFFF; dwAddr ++)
		{
			if( g_dwNumberOfCommentsInArray > MAX_NUMBER_OF_MARKED_LABELS )
				break;

			iType = _Findnextname( szName);
			if( iType != NM_NONAME)
			{
			_N:
				int iCommLen = strlen( szName)+64;
				if( iCommLen > 256) iCommLen = 256;

				char *szComment = (char*)malloc( iCommLen);
				memset( szComment, 0, iCommLen );

				char szPrefix[ 20] = "";

				switch( iType){
					case NM_EXPORT:	strcat( szPrefix, "EXPORT:   "); break;
					case NM_IMPORT:	strcat( szPrefix, "IMPORT:   "); break;
					case NM_LIBRARY:strcat( szPrefix, "LIBRARY:  "); break;
				}
				
				sprintf_s( szComment, iCommLen, "%s <%s>", ((strlen(szPrefix)>0)? szPrefix : ""), szName );

				char szCurrComment[ 256] = "";

				// Checking if there is existing comment
				{
					int iLen = _Findname( dwAddr, NM_COMMENT, szCurrComment);
					if( iLen)
					{
						strcat_s( szComment, iCommLen, ",  ");
						strcat_s( szComment, iCommLen, szCurrComment);
						_Insertname( dwAddr, NM_COMMENT, NULL);
					}
				}
				
				// Insert new comment
				_Insertname( dwAddr, NM_COMMENT, szComment);
				
				g_dwHandleOfCommentsArray[ g_dwNumberOfCommentsInArray] = dwAddr;
				g_dwNumberOfCommentsInArray++;

				free( szComment);
			}
		}
	}else
	{
		char szName[ 256] = "";

		for( unsigned u = 0; u < g_dwNumberOfCommentsInArray; u++)
		{
			memset( szName, 0, 256);
			_Findname( g_dwHandleOfCommentsArray[ u], NM_COMMENT, szName);

			if( strstr( szName, ">, ") )
			{
				// This name has been modified by this plugin
				char szOriginal[256] = "";
				int nAddr = (int(strstr( szName, ">,  "))+4);
				strncpy( szOriginal, (const char*)nAddr, strlen( szName)-nAddr);

				_Insertname( g_dwHandleOfCommentsArray[ u], NM_COMMENT, NULL);
				_Insertname( g_dwHandleOfCommentsArray[ u], NM_COMMENT, szOriginal);
			}

			memset( (void*)g_dwHandleOfCommentsArray, 0, 4*g_dwNumberOfCommentsInArray);
			g_dwNumberOfCommentsInArray = 0;

			free( (void*)g_dwHandleOfCommentsArray );
		}

		bSearchForLabels = true;

	}

	return 0;
}

void MarkProceduresEntryPoints	( )
{
	DWORD dwID = 0;
	CreateThread( NULL, 0, _MarkProceduresEntryPoints, 0, 0, &dwID);
}

#endif
////////////////////////////////////////////////////////////////////////

