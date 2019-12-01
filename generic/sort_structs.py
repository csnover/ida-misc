# https://github.com/csnover/ida-misc
#
# Sorts all the structs in a database in case-insensitive alphabetical order.

import ida_struct;
from idaapi import BADADDR;

structs = []

idx = ida_struct.get_first_struc_idx()
while idx != BADADDR:
    id = ida_struct.get_struc_by_idx(idx)
    name = ida_struct.get_struc_name(id)
    structs.append((name, ida_struct.get_struc(id)))
    idx = ida_struct.get_next_struc_idx(idx)

structs.sort(key=lambda t: t[0].lower())

for i, t in enumerate(structs):
    ida_struct.set_struc_idx(t[1], i)
