package donut

// Windows GUIDs used by donut for COM/CLR initialization

// IID_IUnknown {00000000-0000-0000-C000-000000000046}
var IID_IUnknown = GUID{
	Data1: 0x00000000,
	Data2: 0x0000,
	Data3: 0x0000,
	Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
}

// IID_IDispatch {00020400-0000-0000-C000-000000000046}
var IID_IDispatch = GUID{
	Data1: 0x00020400,
	Data2: 0x0000,
	Data3: 0x0000,
	Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
}

// CLR MetaHost
// CLSID_CLRMetaHost {9280188D-0E8E-4867-B30C-7FA83884E8DE}
var CLSID_CLRMetaHost = GUID{
	Data1: 0x9280188D,
	Data2: 0x0E8E,
	Data3: 0x4867,
	Data4: [8]byte{0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE},
}

// IID_ICLRMetaHost {D332DB9E-B9B3-4125-8207-A14884F53216}
var IID_ICLRMetaHost = GUID{
	Data1: 0xD332DB9E,
	Data2: 0xB9B3,
	Data3: 0x4125,
	Data4: [8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16},
}

// IID_ICLRRuntimeInfo {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
var IID_ICLRRuntimeInfo = GUID{
	Data1: 0xBD39D1D2,
	Data2: 0xBA2F,
	Data3: 0x486A,
	Data4: [8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91},
}

// CorRuntimeHost
// CLSID_CorRuntimeHost {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E}
var CLSID_CorRuntimeHost = GUID{
	Data1: 0xCB2F6723,
	Data2: 0xAB3A,
	Data3: 0x11D2,
	Data4: [8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E},
}

// IID_ICorRuntimeHost {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}
var IID_ICorRuntimeHost = GUID{
	Data1: 0xCB2F6722,
	Data2: 0xAB3A,
	Data3: 0x11D2,
	Data4: [8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E},
}

// IID_AppDomain {05F696DC-2B29-3663-AD8B-C4389CF2A713}
var IID_AppDomain = GUID{
	Data1: 0x05F696DC,
	Data2: 0x2B29,
	Data3: 0x3663,
	Data4: [8]byte{0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13},
}

// VBScript/JScript GUIDs
// CLSID_VBScript {B54F3741-5B07-11CF-A4B0-00AA004A55E8}
var CLSID_VBScript = GUID{
	Data1: 0xB54F3741,
	Data2: 0x5B07,
	Data3: 0x11CF,
	Data4: [8]byte{0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8},
}

// CLSID_JScript {F414C260-6AC0-11CF-B6D1-00AA00BBBB58}
var CLSID_JScript = GUID{
	Data1: 0xF414C260,
	Data2: 0x6AC0,
	Data3: 0x11CF,
	Data4: [8]byte{0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58},
}

// IID_IHost (IHost interface) {91afbd1b-5feb-43f5-b028-e2ca960617ec}
var IID_IHost = GUID{
	Data1: 0x91AFBD1B,
	Data2: 0x5FEB,
	Data3: 0x43F5,
	Data4: [8]byte{0xB0, 0x28, 0xE2, 0xCA, 0x96, 0x06, 0x17, 0xEC},
}

// IID_IActiveScript {BB1A2AE1-A4F9-11CF-8F20-00805F2CD064}
var IID_IActiveScript = GUID{
	Data1: 0xBB1A2AE1,
	Data2: 0xA4F9,
	Data3: 0x11CF,
	Data4: [8]byte{0x8F, 0x20, 0x00, 0x80, 0x5F, 0x2C, 0xD0, 0x64},
}

// IID_IActiveScriptSite {DB01A1E3-A42B-11CF-8F20-00805F2CD064}
var IID_IActiveScriptSite = GUID{
	Data1: 0xDB01A1E3,
	Data2: 0xA42B,
	Data3: 0x11CF,
	Data4: [8]byte{0x8F, 0x20, 0x00, 0x80, 0x5F, 0x2C, 0xD0, 0x64},
}

// IID_IActiveScriptSiteWindow {D10F6761-83E9-11CF-8F20-00805F2CD064}
var IID_IActiveScriptSiteWindow = GUID{
	Data1: 0xD10F6761,
	Data2: 0x83E9,
	Data3: 0x11CF,
	Data4: [8]byte{0x8F, 0x20, 0x00, 0x80, 0x5F, 0x2C, 0xD0, 0x64},
}

// IID_IActiveScriptParse32 {BB1A2AE2-A4F9-11CF-8F20-00805F2CD064}
var IID_IActiveScriptParse32 = GUID{
	Data1: 0xBB1A2AE2,
	Data2: 0xA4F9,
	Data3: 0x11CF,
	Data4: [8]byte{0x8F, 0x20, 0x00, 0x80, 0x5F, 0x2C, 0xD0, 0x64},
}

// IID_IActiveScriptParse64 {C7EF7658-E1EE-480E-97EA-D52CB4D76D17}
var IID_IActiveScriptParse64 = GUID{
	Data1: 0xC7EF7658,
	Data2: 0xE1EE,
	Data3: 0x480E,
	Data4: [8]byte{0x97, 0xEA, 0xD5, 0x2C, 0xB4, 0xD7, 0x6D, 0x17},
}

// SetInstanceGUIDs populates all GUIDs in a DonutInstance
func SetInstanceGUIDs(inst *DonutInstance) {
	inst.XIID_IUnknown = IID_IUnknown
	inst.XIID_IDispatch = IID_IDispatch
	inst.XCLSID_CLRMetaHost = CLSID_CLRMetaHost
	inst.XIID_ICLRMetaHost = IID_ICLRMetaHost
	inst.XIID_ICLRRuntimeInfo = IID_ICLRRuntimeInfo
	inst.XCLSID_CorRuntimeHost = CLSID_CorRuntimeHost
	inst.XIID_ICorRuntimeHost = IID_ICorRuntimeHost
	inst.XIID_AppDomain = IID_AppDomain
	inst.XIID_IActiveScript = IID_IActiveScript
	inst.XIID_IActiveScriptSite = IID_IActiveScriptSite
	inst.XIID_IActiveScriptSiteWindow = IID_IActiveScriptSiteWindow
	inst.XIID_IActiveScriptParse32 = IID_IActiveScriptParse32
	inst.XIID_IActiveScriptParse64 = IID_IActiveScriptParse64
}

// SetScriptGUID sets the CLSID for VBS or JS
func SetScriptGUID(inst *DonutInstance, moduleType int) {
	switch moduleType {
	case DONUT_MODULE_VBS:
		inst.XCLSID_ScriptLanguage = CLSID_VBScript
	case DONUT_MODULE_JS:
		inst.XCLSID_ScriptLanguage = CLSID_JScript
	}
}
