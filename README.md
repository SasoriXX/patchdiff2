patchdiff2
==========

IDA binary differ. Since code.google.com/p/patchdiff2/ seemed abandoned, I did the obvious thing…
And that version seemed abandoned as well, so I did the next obvious thing(?)

Note
====

Updated to build/run with all IDA versions after 6.5 (currently through 7.0)

Windows note
============

vs directory updated to build with Visual Studio 2013 and later

Build note
============

The Visual Studio project and the Unix Makefile utilize relative paths to the SDK include directory.
You should clone into &lt;SDKDIR&gt;/plugins/
