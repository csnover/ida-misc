// https://github.com/csnover/ida-misc
//
// Copy defined field names and comments from one struct to another.

#include <idc.idc>

static main() {
	auto from = GetStrucIdByName(AskStr("", "Copy from"));
	auto to = GetStrucIdByName(AskStr("", "Copy to"));

	if (from == -1 || to == -1) {
		Warning("Nothing to do\n");
		return;
	}

	auto i = GetFirstMember(from);
	auto size = GetStrucSize(to);
	while (i < size) {
		auto tname = GetMemberName(to, i);
		auto name = GetMemberName(from, i);
		auto comment = GetMemberComment(from, i, 0);
		auto rcomment = GetMemberComment(from, i, 1);
		auto s = GetMemberSize(from, i);
		auto ts = GetMemberSize(to, i);

		if (s <= 0 && name == "") {
			i++;
			continue;
		}

		if (substr(name, 0, 6) == "field_") {
			i = i + s;
			continue;
		}

		if (s <= 0 || ts <= 0 || tname == -1 || name == -1) {
			Warning("Failed on %d: %s\n", i, name);
			return;
		}

		SetMemberName(to, i, name);
		if (comment != "") {
			SetMemberComment(to, i, comment, 0);
		}
		if (rcomment != "") {
			SetMemberComment(to, i, rcomment, 1);
		}
		i = i + s;
	}
}
