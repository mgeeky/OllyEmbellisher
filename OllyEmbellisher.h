
#include "Plugin.h"
#include "resource.h"


#define OLLYEMBELLISHER_VERSION				"0.1"		// Must be less then 5 chars length

#define STR_CLEAN_DISASM_POPUP				"Clean Disassemble popup menu"
#define STR_ESC_CLOSES_CHILD				"Escape key closes child window"
#define STR_MARK_PROCEDURES_EPES			"Mark procedures entry points by setting comments"
#define STR_ALLOW_EIP_MODIFICATION			"Allow EIP Modification"
#define STR_REPLACE_DETACH					"Replace OllyAdvanced Detach MenuItem"

#define DETACH_DEBUGGER_MENUITEM			0x850A

// Specifies how much labels is to mark
#define MAX_NUMBER_OF_MARKED_LABELS			10000

//#define USE_DETACHING_CODE				// Specifies wheter to compile "Detaching" code
//#define USE_MARK_ENTRYPOINTS			// Specifies wheter to compile "Entry points" marking code
 

//:::::::::::::::::::::::::::::::::::::;
typedef struct _SYSTEM_HANDLE_ENTRY 
{
    ULONG			OwnerPid;		// ProcessID of handle owner
    BYTE			ObjectType;		// Type of handle (i.e. HANDLE_TYPE_PROCESS)
    BYTE			HandleFlags;	// 
    USHORT			HandleValue;	// Handle value
    PVOID			ObjectPointer;	// 
    ACCESS_MASK		GrantedAccess;	// Security attributes
} SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY ;
 
typedef struct _SYSTEM_HANDLE_INFORMATION 
{
    ULONG				HandleCount;	// Number of found handles
    SYSTEM_HANDLE_ENTRY Handles[1];		// SYSTEM_HANDLE_ENTRY structures table ( 1 means nothing)
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION ;



////////////////////////////////////////////////////////////////////////
//
//extc int _export	ODBG_Plugininit		(int iOllyDbgVersion, HWND, ULONG );
//extc void _export	ODBG_Plugindestroy	(void);
//extc int _export 	ODBG_Plugindata		(char *szShortName);
//extc int _export	ODBG_Pluginmenu		(int origin,char data[4096],void *item);
//extc void _export	ODBG_Pluginaction	(int origin,int action,void *item);
//extc void _export	ODBG_Pluginreset	(void);
//extc int _export	ODBG_Pluginclose	(void);
//extc void _export	ODBG_Plugindestroy	(void);
