/* Minimal EAX shim for Optima.
 *
 * Old Ubisoft titles (Beyond Good & Evil's SettingsApplication, Splinter Cell)
 * require Creative's EAX runtime: they LoadLibrary("eax.dll") and call
 * EAXDirectSoundCreate8 to open an EAX-capable DirectSound device. Creative EAX
 * hardware/drivers don't exist under Proton, so that fails and the game refuses to
 * start ("EAX not properly installed. Please install Creative EAX.").
 *
 * This shim provides eax.dll: EAXDirectSoundCreate8/EAXDirectSoundCreate simply
 * forward to plain DirectSound (which Wine implements). The EAX environmental
 * reverb effects are dropped, but the ownership check passes and audio works.
 */
#define DIRECTSOUND_VERSION 0x0800
#include <windows.h>
#include <dsound.h>

typedef HRESULT (WINAPI *pDSC8)(LPCGUID, LPDIRECTSOUND8*, LPUNKNOWN);
typedef HRESULT (WINAPI *pDSC)(LPCGUID, LPDIRECTSOUND*, LPUNKNOWN);

__declspec(dllexport) HRESULT WINAPI EAXDirectSoundCreate8(LPCGUID dev, LPDIRECTSOUND8* pp, LPUNKNOWN outer) {
    HMODULE h = LoadLibraryA("dsound.dll");
    if (!h) return E_FAIL;
    pDSC8 f = (pDSC8)GetProcAddress(h, "DirectSoundCreate8");
    if (!f) return E_FAIL;
    return f(dev, pp, outer);
}

__declspec(dllexport) HRESULT WINAPI EAXDirectSoundCreate(LPCGUID dev, LPDIRECTSOUND* pp, LPUNKNOWN outer) {
    HMODULE h = LoadLibraryA("dsound.dll");
    if (!h) return E_FAIL;
    pDSC f = (pDSC)GetProcAddress(h, "DirectSoundCreate");
    if (!f) return E_FAIL;
    return f(dev, pp, outer);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID x) { return TRUE; }
