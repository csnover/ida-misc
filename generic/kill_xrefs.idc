// https://github.com/csnover/ida-misc
//
// Sometimes IDA autoanalysis creates bogus xrefs. This quickly deletes all
// xrefs to the address at the cursor.

#include <idc.idc>

static main() {
	auto x;
	auto ea = ScreenEA();
	for (x = RfirstB(ea); x != BADADDR; x = RnextB(ea, x)) {
		Message("Deleting %x\n", x);
		DelCodeXref(x, ea, 0);
	}
	for (x = DfirstB(ea); x != BADADDR; x = DnextB(ea, x)) {
		Message("Deleting %x\n", x);
		auto n;
		for (n = 0; n <= 1; n++) {
			auto yes = GetOpType(x, n) == 2 || GetOpType(x, n) == 5;
			if (yes && GetOperandValue(x, n) == ea) {
				OpNumber(x, n);
			}
		}
		del_dref(x, ea);
	}
}
