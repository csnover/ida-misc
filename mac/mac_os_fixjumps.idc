// https://github.com/csnover/ida-misc
//
// This script is adapted from the one originally published at
// <https://github.com/mietek/theunarchiver/wiki/Disassembling68KMacExecutables>.
// This version supports multiple code worlds and also resolves references to
// jump table entries that are loaded to registers or pushed to the stack.
//
// Fixes up references to Mac A5-world jump table entries. This script supports
// multiple code worlds; this example has the default world plus a second world
// at CODE 11512. Adjust as needed.
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
		this.jumptable = res + 20;
		this.tablesize = Dword(res + 12);
		this.a5offs = Dword(res + 16);
		this.minaddr = minaddr;
		this.maxaddr = maxaddr;
	}
}

static main() {
	auto code0 = world(0, 0, MAXADDR);
	auto code11512 = world(11512, 0x22090, 0x5a1c2);

	if (code0 == MAXADDR) {
		return;
	}

	auto count = 0;
	auto addr = 0;
	while ((addr = FindCode(addr, SEARCH_DOWN)) != BADADDR) {
		if (GetOpType(addr, 0) != 4) {
			continue;
		}

		auto mnem = GetMnem(addr);
		if (mnem != "jsr" && mnem != "jmp" && mnem != "lea" && mnem != "pea") {
			continue;
		}

		auto op = GetOpnd(addr, 0);
		if (substr(op, strlen(op) - 4, -1) != "(a5)") {
			continue;
		}

		auto world;
		if (addr >= code11512.minaddr && addr <= code11512.maxaddr) {
			world = code11512;
		} else {
			world = code0;
		}

		auto opoffs = GetOperandValue(addr, 0);

		auto jumpentry = world.jumptable - world.a5offs - 2 + opoffs;
		auto jumpresid = ltoa(Word(jumpentry + 4), 10);
		auto resoffs = LocByName("CODEResource" + jumpresid);
		auto funcoffs = resoffs + 8 + Word(jumpentry + 0);

		if (opoffs < world.a5offs) {
			continue;
		}

		if (opoffs < 0 || opoffs >= world.tablesize + world.a5offs) {
			Message("%x: Skipping out-of-range jump %x(a5)\n", opoffs, addr);
			continue;
		}

		auto tableoffs = world.a5offs + 2;

		// IDA will not let us IDCs delete its self-generated code xrefs, so
		// given the option to either have bogus xrefs to data in the jump
		// table, or weird offsets on the jmp/jsr instructions, currently I
		// choose weird offsets. This alternate code would delete the bad offset
		// and replace it with the correct one, if IDA would allow it.
		// OpOffEx(addr, 0, REF_OFF32, -1, world.jumptable, tableoffs);
		// DelCodeXref(addr, world.jumptable + opoffs, 0);
		// AddCodeXref(addr, world.jumptable + opoffs - tableoffs, fl_CF | XREF_USER);
		OpOffEx(addr, 0, REF_OFF32, -1, world.jumptable - tableoffs, 0);
		AddCodeXref(addr, funcoffs, fl_CF | XREF_USER);
		count++;
	}

	Message("Updated %d jumps\n", count);
}
