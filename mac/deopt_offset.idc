// https://github.com/csnover/ida-misc
//
// Given C code like:
//
// struct Point {
//   short x;
//   short y;
// }
//
// struct Points {
//   long count;
//   Point data[10];
// }
//
// struct Foo {
//   long foo;
//   Points points;
// }
//
// Foo f;
// int i = 0;
// f.points.data[2 + i].x;
//
// A compiler may optimise this into:
//
// moveq #0,d0;
// shl.w #2,d0;
// lea $10(a0),a0;
// move.w (a0,d0.w),d0;
//
// Where $10 is the combination of
//    offsetof(Foo.points)
//  + offsetof(Points.data)
//  + sizeof(Point) * 2
//
// This script, when given `Point` as the item struct and `Foo` as the base
// struct, will convert the offset into a manual operand:
//
// lea Foo.points.data-2*sizeof(Point)(a0),a0;

#include <idc.idc>

static main() {
	auto base_struct_name = AskStr("Score", "Base struct name");
	if (base_struct_name == "") {
		return;
	}

	auto item_name = AskStr("", "Item struct name or size");
	if (item_name == "") {
		return;
	}

	auto num_items = AskLong(6, "Number of items");
	if (num_items <= 0) {
		return;
	}

	auto item_size;
	if (atol(item_name) != 0) {
		item_size = atol(item_name);
	} else {
		item_size = GetStrucSize(GetStrucIdByName(item_name));
		item_name = sprintf("sizeof(%s)", item_name);
	}

	auto ea = ScreenEA();
	auto n = 0;
	if (GetOpType(ea, 1) == 4) {
		if (GetOpType(ea, 0) == 4) {
			n = AskLong(-1, "Which operand?");
			if (n != 0 && n != 1) {
				return;
			}
		} else {
			n = 1;
		}
	}

	auto offset = GetOperandValue(ea, n) + num_items * item_size;
	auto real_offset = offset;

	auto struct_id = GetStrucIdByName(base_struct_name);
	auto object_path = base_struct_name;
	for (;;) {
		auto member_name = GetMemberName(struct_id, offset);
		if (member_name == "" || member_name == -1) {
			Warning("Could not find a member of %s at 0x%x; parent %s", GetStrucName(struct_id), offset, object_path);
			return;
		}

		object_path = object_path + "." + member_name;

		auto member_offset = GetMemberOffset(struct_id, member_name);
		if (member_offset == offset) {
			break;
		}

		offset = offset - member_offset;
		struct_id = GetMemberStrId(struct_id, member_offset);
		if (struct_id == -1) {
			Warning("Could not find a child struct at %s+0x%x", object_path, member_offset);
			return;
		}
	}

	auto r = GetOpnd(ea, n);
	r = substr(r, strstr(r, "("), strlen(r));

	OpAlt(ea, n, sprintf("%s-%d*%s%s", object_path, num_items, item_name, r));
}
