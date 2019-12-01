// https://github.com/csnover/ida-misc
//
// Fixes up references to Mac A5-world globals by creating structs for the
// above/below A5 sections. This script supports multiple code worlds; this
// example has the default world plus a second world at CODE 11512. Adjust as
// needed.
//
// This script is idempotent.
//
// You must run mac_os_resources.idc before running this script.

#include <idc.idc>

class world {
	world(resid, minaddr, maxaddr) {
		auto ares = ltoa(resid, 10);
		auto res = LocByName("CODEResource" + ares);
		if (res == -1) {
			throw sprintf("No CODE resource %d", resid);
		}
		this.a5above = Dword(res + 16);
		this.a5below = Dword(res + 8);
		this.minaddr = minaddr;
		this.maxaddr = maxaddr;
		this.abovevars = GetStrucIdByName("A5Above" + ares);
		if (this.abovevars == -1) {
			this.abovevars = AddStrucEx(0, "A5Above" + ares, 0);
		}
		this.belowvars = GetStrucIdByName("A5Below" + ares);
		if (this.belowvars == -1) {
			this.belowvars = AddStrucEx(0, "A5Below" + ares, 0);
		}
	}
}

static main() {
	auto code0 = world(0, 0, MAXADDR);
	auto code11512 = world(11512, 0x22090, 0x5a1c2);

	auto count = 0;
	auto addr = 0;
	while ((addr = FindCode(addr, SEARCH_DOWN)) != BADADDR) {
		auto i;
		for (i = 0; i <= 1; ++i) {
			auto mnem = GetMnem(addr);
			if (GetOpType(addr, i) != 4 || mnem == "jsr" || mnem == "jmp") {
				continue;
			}

			auto op = GetOpnd(addr, i);
			if (substr(op, strlen(op) - 4, -1) != "(a5)") {
				continue;
			}

			auto offs = GetOperandValue(addr, i);

			auto inst;
			auto datasize = 1;
			auto datatype = FF_BYTE;
			{
				auto raw = GetDisasm(addr);
				auto idx = strstr(raw, " ");
				inst = substr(raw, 0, idx);

				idx = strstr(inst, ".");
				if (idx != -1) {
					auto s = substr(inst, idx + 1, idx + 2);
					if (s == "l") {
						datasize = 4; datatype = FF_DWRD;
					} else if (s == "w") {
						datasize = 2; datatype = FF_WORD;
					} else if (s != "b") {
						Warning("Weird type %s; aborting!", s);
						return;
					}
				} else if (mnem == "move") {
					Message("Could not interpret data size from move at %x\n", addr);
				}
			}

			auto world;
			if (addr >= code11512.minaddr && addr <= code11512.maxaddr) {
				world = code11512;
			} else {
				world = code0;
			}

			auto varsstruct, structoffs;
			if (offs < 0 && offs >= -world.a5below) {
				varsstruct = world.belowvars;
				structoffs = world.a5below;
				offs = world.a5below + offs;
			} else if (offs >= 0 && offs < world.a5above) {
				varsstruct = world.abovevars;
				structoffs = 0;
			} else {
				continue;
			}

			AddStrucMember(varsstruct, sprintf("field_%x", offs), offs, datatype, -1, datasize);
			OpStroffEx(addr, i, varsstruct, structoffs);
			if (substr(GetOpnd(addr, i), 0, 1) == "-") {
				OpSign(addr, i);
			}
			count++;
		}
	}

	Message("Created %d globals\n", count);
}
