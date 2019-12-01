// https://github.com/csnover/ida-misc
//
// This script is adapted from the one originally published at
// <https://github.com/mietek/theunarchiver/wiki/Disassembling68KMacExecutables>.
// This version fixes up STR# resources, resolves resource name conflicts,
// detects Application VISE compressed data, and handles executables with
// multiple jump tables.
//
// This script should be run only once during initial analysis.
//
// Note that in order to disassemble raw images you may need to patch IDA’s m68k
// processor, since it does not normally allow disassembly of instructions that
// are not word-aligned, but this can happen in the raw image data.

#include <idc.idc>

// It is easy for 'STR ' and 'STR#' to conflict
static make_name_noconflict(addr, name) {
	if (!MakeNameEx(addr, name, SN_NOCHECK|SN_NOWARN)) {
		auto pfix = 0;
		while (!MakeNameEx(addr, sprintf("%s_%d", name, pfix), SN_NOCHECK|SN_NOWARN)) {
			pfix = pfix + 1;
		}
	}
}

static is_normal_code_seg(data) {
	auto datasize = Dword(data);
	auto jumptablesize = Dword(data + 12);
	auto firstjumpoffset = data + 20;
	return jumptablesize > datasize
		|| Word(firstjumpoffset + 2) != 0x3f3c
		|| Word(firstjumpoffset + 6) != 0xa9f0;
}

static make_code_seg(resid, data) {
	auto datasize = Dword(data);
	auto jumptablesize = Dword(data + 12);
	auto firstjumpoffset = data + 20;
	if (is_normal_code_seg(data)) {
		MakeWord(data + 4);
		OpNumber(data + 4, 0);
		MakeComm(data + 4, "Offset of first entry in jump table");

		MakeWord(data + 6);
		OpNumber(data + 6, 0);
		MakeComm(data + 6, "Number of entries in jump table");

		AutoMark(data + 8, AU_CODE);
		AutoMark(data + 8, AU_PROC);
	} else {
		MakeDword(data + 4);
		OpNumber (data + 4, 0);
		MakeComm (data + 4, "Size above A5");

		MakeDword(data + 8);
		OpNumber (data + 8, 0);
		MakeComm (data + 8, "Size of globals");

		MakeDword(data + 12);
		OpNumber (data + 12, 0);
		MakeComm (data + 12, "Length of jump table");

		MakeDword(data + 16);
		OpNumber (data + 16, 0);
		MakeComm (data + 16, "A5 offset of jump table");

		MakeNameEx(data + 20, sprintf("JumpTable%d", resid), 0);
	}
}

static process_jumptable(resid, jumptable, size) {
	auto i;
	for (i = 0; i < size; i = i + 8) {
		auto jumpentry = jumptable + i;

		auto resoffs = LocByName(sprintf("CODEResource%d", Word(jumpentry + 4)));

		MakeWord(jumpentry);
		OpOffEx (jumpentry, 0, REF_OFF32, -1, resoffs, -8);
		MakeComm(jumpentry, "Offset of function");

		if (Word(jumpentry + 2) != 0x3f3c || Word(jumpentry + 6) != 0xa9f0) {
			auto msg;
			if (i == 8 && Word(jumpentry) == 0xa89f) {
				Warning("CODEResource%d jump table is compressed by Application VISE.\n", resid);
			} else {
				Warning("CODEResource%d jump table is invalid starting at absolute offset $%x.\n", resid, jumpentry);
			}
			return;
		}

		MakeWord(jumpentry + 2);
		OpNumber(jumpentry + 2, 0);
		MakeComm(jumpentry + 2, "Push instruction");

		MakeWord(jumpentry + 4);
		OpNumber(jumpentry + 4, 0);
		MakeComm(jumpentry + 4, "Resource ID to push");

		MakeWord(jumpentry + 6);
		OpNumber(jumpentry + 6, 0);
		MakeComm(jumpentry + 6, "LoadSeg instruction");

		auto target = resoffs + 8 + Word(jumpentry);
		MakeCode(target);
		AutoMark(target, AU_PROC);
	}
}

static make_strlist_seg(resid, data) {
	auto numstr = Word(data + 4);
	MakeWord(data + 4);
	MakeComm(data + 4, "Number of entries in string table");

	auto strtype = GetLongPrm(INF_STRTYPE);
	SetLongPrm(INF_STRTYPE, ASCSTR_PASCAL);

	auto strdata = data + 6;
	auto i;
	for (i = 0; i < numstr; i++) {
		auto slen = Byte(strdata);
		MakeStr(strdata, strdata + slen + 1);
		strdata = strdata + slen + 1;
	}

	SetLongPrm(INF_STRTYPE, strtype);
}

static make_data_seg(resid, data) {
	auto size = Dword(data);
	MakeByte(data + 4);
	MakeArray(data + 4, size);
	SetArrayFormat(data + 4, 0, 0, 0);
}

static make_resource(resdata, resnamelist, resname, ref) {
	auto resid = Word(ref);
	MakeWord(ref);
	OpNumber(ref, 0);
	MakeComm(ref, "Resource ID");

	MakeWord(ref + 2);
	OpOffEx (ref + 2, 0, REF_OFF32, -1, resnamelist, 0);
	MakeComm(ref + 2, "Offset to resource name");
	if (Word(ref + 2) != 0xffff) {
		auto resnameoffs = resnamelist + Word(ref + 2);
		auto slen = Byte(resnameoffs);
		SetLongPrm(resnameoffs, ASCSTR_PASCAL);
		MakeStr(resnameoffs, resnameoffs + slen + 1);
	}

	auto attrs = Byte(ref + 4);
	MakeDword(ref + 4);
	OpOffEx  (ref + 4, 0, REF_OFF32, -1, resdata, attrs << 24);
	MakeComm (ref + 4, "Offset to resource data plus attributes");

	MakeDword(ref + 8);
	OpNumber (ref + 8, 0);
	MakeComm (ref + 8, "Reserved for handle to resource");

	auto data = resdata + Dword(ref + 4) - (attrs << 24);
	make_name_noconflict(data, sprintf("%sResource%d", resname, resid));

	MakeDword(data);
	OpNumber (data, 0);
	MakeComm (data, "Length of resource data");

	auto vise = Dword(data + 4);
	if (vise == 0xa89f000c) {
		Message("%sResource%d is compressed by Application VISE; skipping\n", resname, resid);
	} else if (resname == "CODE") {
		make_code_seg(resid, data);
	} else if (resname == "STR#") {
		make_strlist_seg(resid, data);
	} else {
		make_data_seg(resid, data);
	}
}

static make_resource_type(resdata, resnamelist, restypelist, entry) {
	MakeStr (entry, entry + 4);
	MakeComm(entry, "Resource type");

	MakeWord(entry + 4);
	OpNumber(entry + 4, 0);
	MakeComm(entry + 4, "Number of resource of this type minus one");

	MakeWord(entry + 6);
	OpOffEx (entry + 6, 0, REF_OFF32, -1, restypelist, 2);
	MakeComm(entry + 6, "Offset of reference list for this type");

	auto reflist = restypelist + Word(entry + 6) - 2;
	auto resname = GetString(entry, 4, ASCSTR_C);
	make_name_noconflict(reflist, "ReferenceList" + resname);

	auto numrefs = Word(entry + 4) + 1;
	auto i;
	for (i = 0; i < numrefs; i++) {
		make_resource(resdata, resnamelist, resname, reflist + i * 12);
	}
}

static get_num_refs(resname) {
	auto restypelist = LocByName("ResourceTypeList");
	auto numtypes = Word(restypelist - 2) + 1;

	auto i;
	for (i = 0; i < numtypes; i++) {
		auto entry = restypelist + i * 8;
		auto testresname = GetString(entry, 4, ASCSTR_C);
		if (testresname == resname) {
			return Word(entry + 4) + 1;
		}
	}

	return 0;
}

static main() {
	auto base = FirstSeg();

	OpOffEx (base, 0, REF_OFF32, -1, 0, -base);
	MakeComm(base, "Offset to resource data");

	OpOffEx (base + 4, 0, REF_OFF32, -1, 0, -base);
	MakeComm(base + 4, "Offset to resource map");

	MakeDword(base + 8);
	OpNumber (base + 8, 0);
	MakeComm (base + 8, "Length of resource data");

	MakeDword(base + 12);
	OpNumber (base + 12, 0);
	MakeComm (base + 12, "Length of resource map");

	auto resdata = base + Dword(base);
	MakeNameEx(resdata, "ResourceData", 0);

	// Prevent IDA from doing code autoanalysis into the executable header
	MakeByte(base + 16);
	MakeArray(base + 16, Dword(base) - 16);
	SetArrayFormat(base + 16, 0, 0, 0);

	auto resmap = base + Dword(base + 4);
	MakeNameEx(resmap, "ResourceMap", 0);

	OpOffEx (resmap, 0, REF_OFF32, -1, 0, -base);
	MakeComm(resmap, "Offset to resource data");

	OpOffEx (resmap + 4, 0, REF_OFF32, -1, 0, -base);
	MakeComm(resmap + 4, "Offset to resource map");

	MakeDword(resmap + 8);
	OpNumber (resmap + 8, 0);
	MakeComm (resmap + 8, "Length of resource data");

	MakeDword(resmap + 12);
	OpNumber (resmap + 12, 0);
	MakeComm (resmap + 12, "Length of resource map");

	MakeDword(resmap + 16);
	OpNumber (resmap + 16, 0);
	MakeComm (resmap + 16, "Reserved for handle to next resource map");

	MakeWord(resmap + 20);
	OpNumber(resmap + 20, 0);
	MakeComm(resmap + 20, "Reserved for file reference number");

	MakeWord(resmap + 22);
	OpNumber(resmap + 22, 0);
	MakeComm(resmap + 22, "Resource fork attributes");

	MakeWord(resmap + 24);
	OpOffEx (resmap + 24, 0, REF_OFF32, -1, resmap, -2);
	MakeComm(resmap + 24, "Offset to type list");

	MakeWord(resmap + 26);
	OpOffEx (resmap + 26, 0, REF_OFF32, -1, resmap, -2);
	MakeComm(resmap + 26, "Offset to name list");

	auto restypelist = resmap + Word(resmap + 24) + 2;
	MakeNameEx(restypelist, "ResourceTypeList", 0);

	auto resnamelist = resmap + Word(resmap + 26);
	MakeNameEx(resnamelist, "ResourceNameList", 0);

	MakeWord(resmap + 28);
	OpNumber(resmap + 28, 0);
	MakeComm(resmap + 28, "Number of types minus one");

	auto numtypes = Word(resmap + 28) + 1;
	auto i;
	for (i = 0; i < numtypes; i++) {
		make_resource_type(resdata, resnamelist, restypelist, restypelist + i * 8);
	}

	// Jumps into CODE segments can only be analysed once resources are fully
	// constructed since otherwise they cannot be referenced by ID
	auto codetable = LocByName("ReferenceListCODE");
	auto numrefs = get_num_refs("CODE");
	for (i = 0; i < numrefs; i++) {
		auto entry = codetable + i * 12;
		auto data = resdata + (Dword(entry + 4) & ((1 << 24) - 1));
		if (!is_normal_code_seg(data)) {
			auto resid = Word(entry);
			auto jumptable = data + 20;
			auto jumptablesize = Dword(data + 12);
			process_jumptable(resid, jumptable, jumptablesize);
		}
	}
}
