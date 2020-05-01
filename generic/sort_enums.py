# https://github.com/csnover/ida-misc
#
# Sorts all the enums in a database in case-insensitive alphabetical order.

import ida_enum;

enums = []

for i in range(0, ida_enum.get_enum_qty()):
    id = ida_enum.getn_enum(i)
    name = ida_enum.get_enum_name(id)
    enums.append((name, id))

enums.sort(key=lambda t: t[0].lower())

for i, t in enumerate(enums):
    ida_enum.set_enum_idx(t[1], i)
