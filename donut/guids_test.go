package donut

import (
	"testing"
)

func TestGUIDSize(t *testing.T) {
	// GUID should be 16 bytes
	var g GUID
	expectedSize := 16 // 4 + 2 + 2 + 8

	actualSize := 4 + 2 + 2 + len(g.Data4)
	if actualSize != expectedSize {
		t.Errorf("GUID fields size = %d, expected %d", actualSize, expectedSize)
	}
}

func TestKnownGUIDs(t *testing.T) {
	// Verify some known GUIDs have expected values
	guids := map[string]GUID{
		"IID_IUnknown":        IID_IUnknown,
		"CLSID_CLRMetaHost":   CLSID_CLRMetaHost,
		"IID_ICLRMetaHost":    IID_ICLRMetaHost,
		"IID_ICLRRuntimeInfo": IID_ICLRRuntimeInfo,
		"IID_ICorRuntimeHost": IID_ICorRuntimeHost,
		"IID_AppDomain":       IID_AppDomain,
	}

	// Just verify they're not all zeros in critical fields
	for name, guid := range guids {
		hasNonZero := guid.Data1 != 0 || guid.Data2 != 0 || guid.Data3 != 0
		if !hasNonZero {
			// Check Data4 for non-zero bytes
			for _, v := range guid.Data4 {
				if v != 0 {
					hasNonZero = true
					break
				}
			}
		}

		// IID_IUnknown has zeros in first fields but non-zero in Data4
		if !hasNonZero && name != "IID_IUnknown" {
			t.Errorf("GUID %s appears to be all zeros", name)
		}
	}
}

func TestSetInstanceGUIDs(t *testing.T) {
	instance := &DonutInstance{}

	SetInstanceGUIDs(instance)

	// Verify GUIDs were set (check XCLSID_CLRMetaHost which should be non-zero)
	if instance.XCLSID_CLRMetaHost.Data1 == 0 &&
		instance.XCLSID_CLRMetaHost.Data2 == 0 &&
		instance.XCLSID_CLRMetaHost.Data3 == 0 {
		allZero := true
		for _, v := range instance.XCLSID_CLRMetaHost.Data4 {
			if v != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("XCLSID_CLRMetaHost not set by SetInstanceGUIDs")
		}
	}
}

func TestScriptGUIDs(t *testing.T) {
	// Verify script engine GUIDs exist
	scriptGUIDs := []struct {
		name string
		guid GUID
	}{
		{"CLSID_VBScript", CLSID_VBScript},
		{"CLSID_JScript", CLSID_JScript},
		{"IID_IActiveScript", IID_IActiveScript},
		{"IID_IActiveScriptSite", IID_IActiveScriptSite},
		{"IID_IActiveScriptParse32", IID_IActiveScriptParse32},
		{"IID_IActiveScriptParse64", IID_IActiveScriptParse64},
	}

	for _, tc := range scriptGUIDs {
		// Just verify the GUID exists and isn't all zeros
		hasNonZero := tc.guid.Data1 != 0 || tc.guid.Data2 != 0 || tc.guid.Data3 != 0
		for _, v := range tc.guid.Data4 {
			if v != 0 {
				hasNonZero = true
				break
			}
		}
		if !hasNonZero {
			t.Errorf("%s is all zeros", tc.name)
		}
	}
}

func TestSetScriptGUID(t *testing.T) {
	instance := &DonutInstance{}

	// Test VBS
	SetScriptGUID(instance, DONUT_MODULE_VBS)
	if instance.XCLSID_ScriptLanguage.Data1 == 0 {
		t.Error("VBS GUID not set properly")
	}

	// Test JS
	instance2 := &DonutInstance{}
	SetScriptGUID(instance2, DONUT_MODULE_JS)
	if instance2.XCLSID_ScriptLanguage.Data1 == 0 {
		t.Error("JS GUID not set properly")
	}
}
