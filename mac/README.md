# Mac OS Classic scripts

## Usage

1. Load a Mac Resource file into IDA as Binary file. Set the processor type to
   68030. (Earlier processor types may not identify A-traps correctly.) All
   options can be left at their defaults. If you are loading a MacBinary file,
   set the load offsets appropriately to point to the resource fork.
1. Run `mac_os_resource.idc` for initial analysis. Run this only once.
1. Run `mac_os_fixglobals.idc` to find and create offsets to A5 globals. You
   can run this many times.
1. Run `mac_os_fixjumps.idc` to find and xref all A5 jumps. You can run this
   many times.
