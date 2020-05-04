// https://github.com/csnover/ida-misc
//
// Given C code like:
//
// struct Point {
//   int x;
//   int y;
// }
//
// struct Points {
//   int count;
//   Point data[10];
// }
//
// Points ps;
// int i = 1;
// ps.data[i - 1].x;
//
// A compiler may optimise this into:
//
// mov ebx, 1;
// mov eax, [eax+ebx*8-4];
//
// Where *8 is the sizeof(Point) and -4 is the combination of
//    offsetof(Points.data)
//  + offsetof(Point.x)
//  - sizeof(Point)
//
// This script, when given `Point` as the item struct and `Points` as the base
// struct, will convert the offset into a manual operand:
//
// mov eax, [eax+ebx*8-Points.data.x-size Point];
//
// This script automatically binds to the hotkey Shift+T.

#include <idc.idc>

static main() {
	if (AddHotkey("Shift-T", "deopt_offset") == 0) {
		Message("Registered on hotkey Shift-T\n");
	}
}

static deopt_offset() {
	extern last_struct_name;
	extern last_item_name;
	extern last_num_items;

	auto base_struct_name = AskStr(last_struct_name, "Base struct name");
	if (base_struct_name == "") {
		return;
	}

	auto base_item_name = AskStr(last_item_name, "Item struct name or size");
	if (base_item_name == "") {
		return;
	}

	auto num_items = AskLong(last_num_items, "Index base (e.g. 3 for `foo[i - 3]`)");
	if (num_items <= 0) {
		return;
	}

	auto item_name = base_item_name;
	auto item_size;
	if (atol(item_name) != 0) {
		item_size = atol(item_name);
	} else {
		item_size = GetStrucSize(GetStrucIdByName(item_name));
		item_name = sprintf("size %s", item_name);
	}

	auto ea = ScreenEA();
	auto n;
	auto nt;
	auto mnem = GetMnem(ea);
	auto ot0 = GetOpType(ea, 0);
	auto ot1 = GetOpType(ea, 1);
	if ((ot0 == 4 || ot0 == 5) && ot1 != 4 && ot1 != 5) {
		n = 0;
		nt = ot0;
	} else if ((ot1 == 4 || ot1 == 5) && ot0 != 4 && ot0 != 5) {
		n = 1;
		nt = ot1;
	} else {
		n = AskLong(-1, "Which operand?");
		if (n != 0 && n != 1) {
			return;
		}
		nt = GetOpType(ea, n);
	}

	auto offset;
	if (nt == 4) {
		offset = GetOperandValue(ea, n) + num_items * item_size;
	} else if (nt == 5 && mnem == "sub") {
		offset = num_items * item_size - GetOperandValue(ea, n);
	} else {
		Warning("Cannot adjust operand of type %d", nt);
		return;
	}

	auto real_offset = offset;

	auto struct_id = GetStrucIdByName(base_struct_name);
	auto object_path = base_struct_name;
	auto member_size;
	for (;;) {
		auto struct_size = GetStrucSize(struct_id);
		auto member_name;
		if (offset > struct_size && GetMemberSize(struct_id, struct_size) == 0) {
			// variable size struct
			member_name = GetMemberName(struct_id, struct_size);
		} else {
			member_name = GetMemberName(struct_id, offset);
		}

		if (member_name == "" || member_name == -1) {
			Warning("Could not find a member of %s at 0x%x; parent %s", GetStrucName(struct_id), offset, object_path);
			return;
		}

		object_path = object_path + "." + member_name;

		auto member_offset = GetMemberOffset(struct_id, member_name);
		if (member_offset == offset) {
			member_size = GetMemberSize(struct_id, member_offset);

			if (mnem != "lea") {
				struct_id = GetMemberStrId(struct_id, member_offset);
				while (struct_id != -1) {
					member_name = GetMemberName(struct_id, 0);
					member_size = GetMemberSize(struct_id, 0);
					object_path = object_path + "." + member_name;
					struct_id = GetMemberStrId(struct_id, 0);
				}
			}

			break;
		}

		offset = offset - member_offset;
		struct_id = GetMemberStrId(struct_id, member_offset);

		if (struct_id == -1) {
			Warning("Could not find a child struct at %s+0x%x", object_path, member_offset);
			return;
		}
	}

	last_struct_name = base_struct_name;
	last_item_name = base_item_name;
	last_num_items = num_items;

	if (num_items != 1) {
		item_name = sprintf("(%s*%d)", item_name, num_items);
	}

	if (nt == 4) {
		auto r = GetOpnd(ea, n);
		auto offset_pos = strstr(r, "-") + 1;
		if (offset_pos == 0) {
			auto new_pos = 0;
			while (new_pos != -1) {
				offset_pos = offset_pos + new_pos + 1;
				new_pos = strstr(substr(r, offset_pos, -1), "+");
			}
		}
		r = substr(r, 0, offset_pos - 1);

		if (substr(mnem, 0, 3) == "mov") {
			auto other_r = GetOpnd(ea, 1 - n);
			auto other_size;
			auto r_prefix;
			if (other_r[0] == "q") {
				other_size = 8;
				r_prefix = "qword ptr ";
			} else if (other_r[0] == "e") {
				other_size = 4;
				r_prefix = "dword ptr ";
			} else if (other_size == 2 && strstr("lh", other_r[1]) != -1) {
				other_size = 1;
				r_prefix = "byte ptr ";
			} else {
				other_size = 2;
				r_prefix = "word ptr ";
			}

			auto mnem_ext = substr(mnem, 3, 5);
			if (mnem_ext != "" || (member_size == other_size && substr(r, 0, strlen(r_prefix) - 1) == r_prefix)) {
				r = substr(r, strlen(r_prefix) - 1, -1);
			}
		}

		OpAlt(ea, n, sprintf("%s+%s-%s]", r, object_path, item_name));
	} else if (nt == 5) {
		OpAlt(ea, n, sprintf("%s-%s", item_name, object_path));
	}
}
