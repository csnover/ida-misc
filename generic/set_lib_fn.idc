// https://github.com/csnover/ida-misc
//
// A hotkey binding to name and set a function as a library function in one
// step.

#include <idc.idc>

static set_lib_fn() {
	auto ea = FirstFuncFchunk(ScreenEA());
	auto n = AskIdent("", "Function name?");
	if (ea != BADADDR && n != "") {
		MakeNameEx(ea, n, 0);
		SetFunctionFlags(ea, GetFunctionFlags(ea) | FUNC_LIB);
	}
}

static main() {
	auto key = AskStr("Shift+L", "What hotkey?");
	if (key != "") {
		AddHotkey("Shift+L", "set_lib_fn");
	}
}
