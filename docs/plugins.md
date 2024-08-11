# Plugins

## pslist

To list the processes of a system, use the `pslist` command. This walks the doubly-linked list pointed to by `PsActiveProcessHead` and shows the offset, process name, process ID, the parent process ID, number of threads, number of handles, and date/time when the process started and exited. As of 2.1 it also shows the Session ID and if the process is a Wow64 process (it uses a 32 bit address space on a 64 bit kernel).

This plugin does not detect hidden or unlinked processes (but [psscan](Command-Reference#psscan) can do that).

If you see processes with 0 threads, 0 handles, and/or a non-empty exit time, the process may not actually still be active. For more information, see [The Missing Active in PsActiveProcessHead](http://mnin.blogspot.com/2011/03/mis-leading-active-in.html). Below, you'll notice `regsvr32.exe` has terminated even though its still in the "active" list. 

Also note the two processes `System` and `smss.exe` will not have a Session ID, because System starts before sessions are established and `smss.exe` is the session manager itself. 

    $ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 pslist
    Volatility Foundation Volatility Framework 2.4
    Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                Exit                
    ------------------ -------------------- ------ ------ ------ -------- ------ ------ -------------------- --------------------
    0xfffffa80004b09e0 System                    4      0     78      489 ------      0 2012-02-22 19:58:20                      
    0xfffffa8000ce97f0 smss.exe                208      4      2       29 ------      0 2012-02-22 19:58:20                      
    0xfffffa8000c006c0 csrss.exe               296    288      9      385      0      0 2012-02-22 19:58:24                      
    0xfffffa8000c92300 wininit.exe             332    288      3       74      0      0 2012-02-22 19:58:30                      
    0xfffffa8000c06b30 csrss.exe               344    324      7      252      1      0 2012-02-22 19:58:30                      
    0xfffffa8000c80b30 winlogon.exe            372    324      5      136      1      0 2012-02-22 19:58:31                      
    0xfffffa8000c5eb30 services.exe            428    332      6      193      0      0 2012-02-22 19:58:32                      
    0xfffffa80011c5700 lsass.exe               444    332      6      557      0      0 2012-02-22 19:58:32                      
    0xfffffa8000ea31b0 lsm.exe                 452    332     10      133      0      0 2012-02-22 19:58:32                      
    0xfffffa8001296b30 svchost.exe             568    428     10      352      0      0 2012-02-22 19:58:34                      
    0xfffffa80012c3620 svchost.exe             628    428      6      247      0      0 2012-02-22 19:58:34                      
    0xfffffa8001325950 sppsvc.exe              816    428      5      154      0      0 2012-02-22 19:58:41                      
    0xfffffa80007b7960 svchost.exe             856    428     16      404      0      0 2012-02-22 19:58:43                      
    0xfffffa80007bb750 svchost.exe             880    428     34     1118      0      0 2012-02-22 19:58:43                      
    0xfffffa80007d09e0 svchost.exe             916    428     19      443      0      0 2012-02-22 19:58:43                      
    0xfffffa8000c64840 svchost.exe             348    428     14      338      0      0 2012-02-22 20:02:07                      
    0xfffffa8000c09630 svchost.exe             504    428     16      496      0      0 2012-02-22 20:02:07                      
    0xfffffa8000e86690 spoolsv.exe            1076    428     12      271      0      0 2012-02-22 20:02:10                      
    0xfffffa8000518b30 svchost.exe            1104    428     18      307      0      0 2012-02-22 20:02:10                      
    0xfffffa800094d960 wlms.exe               1264    428      4       43      0      0 2012-02-22 20:02:11                      
    0xfffffa8000995b30 svchost.exe            1736    428     12      200      0      0 2012-02-22 20:02:25                      
    0xfffffa8000aa0b30 SearchIndexer.         1800    428     12      757      0      0 2012-02-22 20:02:26                      
    0xfffffa8000aea630 taskhost.exe           1144    428      7      189      1      0 2012-02-22 20:02:41                      
    0xfffffa8000eafb30 dwm.exe                1476    856      3       71      1      0 2012-02-22 20:02:41                      
    0xfffffa80008f3420 explorer.exe           1652    840     21      760      1      0 2012-02-22 20:02:42                      
    0xfffffa8000c9a630 regsvr32.exe           1180   1652      0 --------      1      0 2012-02-22 20:03:05  2012-02-22 20:03:08 
    0xfffffa8000a03b30 rundll32.exe           2016    568      3       67      1      0 2012-02-22 20:03:16                      
    0xfffffa8000a4f630 svchost.exe            1432    428     12      350      0      0 2012-02-22 20:04:14                      
    0xfffffa8000999780 iexplore.exe           1892   1652     19      688      1      1 2012-02-22 11:26:12                      
    0xfffffa80010c9060 iexplore.exe           2820   1892     23      733      1      1 2012-02-22 11:26:15                      
    0xfffffa8001016060 DumpIt.exe             2860   1652      2       42      1      1 2012-02-22 11:28:59                      
    0xfffffa8000acab30 conhost.exe            2236    344      2       51      1      0 2012-02-22 11:28:59 

By default, `pslist` shows virtual offsets for the `_EPROCESS` but the physical offset can be obtained with the `-P` switch:

    $ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 pslist -P 
    Volatility Foundation Volatility Framework 2.4
    Offset(P)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                Exit                
    ------------------ -------------------- ------ ------ ------ -------- ------ ------ -------------------- --------------------
    0x0000000017fef9e0 System                    4      0     78      489 ------      0 2012-02-22 19:58:20                      
    0x00000000176e97f0 smss.exe                208      4      2       29 ------      0 2012-02-22 19:58:20                      
    0x00000000176006c0 csrss.exe               296    288      9      385      0      0 2012-02-22 19:58:24                      
    0x0000000017692300 wininit.exe             332    288      3       74      0      0 2012-02-22 19:58:30                      
    0x0000000017606b30 csrss.exe               344    324      7      252      1      0 2012-02-22 19:58:30
    ... 

## pstree

To view the process listing in tree form, use the `pstree` command. This enumerates processes using the same technique as `pslist`, so it will also not show hidden or unlinked processes. Child process are indicated using indention and periods. 

    $ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 pstree
    Volatility Foundation Volatility Framework 2.4
    Name                                                  Pid   PPid   Thds   Hnds Time                
    -------------------------------------------------- ------ ------ ------ ------ --------------------
     0xfffffa80004b09e0:System                              4      0     78    489 2012-02-22 19:58:20 
    . 0xfffffa8000ce97f0:smss.exe                         208      4      2     29 2012-02-22 19:58:20 
     0xfffffa8000c006c0:csrss.exe                         296    288      9    385 2012-02-22 19:58:24 
     0xfffffa8000c92300:wininit.exe                       332    288      3     74 2012-02-22 19:58:30 
    . 0xfffffa8000c5eb30:services.exe                     428    332      6    193 2012-02-22 19:58:32 
    .. 0xfffffa8000aa0b30:SearchIndexer.                 1800    428     12    757 2012-02-22 20:02:26 
    .. 0xfffffa80007d09e0:svchost.exe                     916    428     19    443 2012-02-22 19:58:43 
    .. 0xfffffa8000a4f630:svchost.exe                    1432    428     12    350 2012-02-22 20:04:14 
    .. 0xfffffa800094d960:wlms.exe                       1264    428      4     43 2012-02-22 20:02:11 
    .. 0xfffffa8001325950:sppsvc.exe                      816    428      5    154 2012-02-22 19:58:41 
    .. 0xfffffa8000e86690:spoolsv.exe                    1076    428     12    271 2012-02-22 20:02:10 
    .. 0xfffffa8001296b30:svchost.exe                     568    428     10    352 2012-02-22 19:58:34 
    ... 0xfffffa8000a03b30:rundll32.exe                  2016    568      3     67 2012-02-22 20:03:16
    ...

## psscan

To enumerate processes using pool tag scanning (`_POOL_HEADER`), use the `psscan` command. This can find processes that previously terminated (inactive) and processes that have been hidden or unlinked by a rootkit. The downside is that rootkits can still hide by overwriting the pool tag values (though not commonly seen in the wild).

    $ python vol.py --profile=Win7SP0x86 -f win7.dmp psscan
    Volatility Foundation Volatility Framework 2.0
     Offset     Name             PID    PPID   PDB        Time created             Time exited             
    ---------- ---------------- ------ ------ ---------- ------------------------ ------------------------ 
    0x3e025ba8 svchost.exe        1116    508 0x3ecf1220 2010-06-16 15:25:25                              
    0x3e04f070 svchost.exe        1152    508 0x3ecf1340 2010-06-16 15:27:40                              
    0x3e144c08 dwm.exe            1540    832 0x3ecf12e0 2010-06-16 15:26:58                              
    0x3e145c18 TPAutoConnSvc.     1900    508 0x3ecf1360 2010-06-16 15:25:41                              
    0x3e3393f8 lsass.exe           516    392 0x3ecf10e0 2010-06-16 15:25:18                              
    0x3e35b8f8 svchost.exe         628    508 0x3ecf1120 2010-06-16 15:25:19                              
    0x3e383770 svchost.exe         832    508 0x3ecf11a0 2010-06-16 15:25:20                              
    0x3e3949d0 svchost.exe         740    508 0x3ecf1160 2010-06-16 15:25:20                              
    0x3e3a5100 svchost.exe         872    508 0x3ecf11c0 2010-06-16 15:25:20                              
    0x3e3f64e8 svchost.exe         992    508 0x3ecf1200 2010-06-16 15:25:24                              
    0x3e45a530 wininit.exe         392    316 0x3ecf10a0 2010-06-16 15:25:15                              
    0x3e45d928 svchost.exe        1304    508 0x3ecf1260 2010-06-16 15:25:28                              
    0x3e45f530 csrss.exe           400    384 0x3ecf1040 2010-06-16 15:25:15                              
    0x3e4d89c8 vmtoolsd.exe       1436    508 0x3ecf1280 2010-06-16 15:25:30                              
    0x3e4db030 spoolsv.exe        1268    508 0x3ecf1240 2010-06-16 15:25:28                              
    0x3e50b318 services.exe        508    392 0x3ecf1080 2010-06-16 15:25:18                              
    0x3e7f3d40 csrss.exe           352    316 0x3ecf1060 2010-06-16 15:25:12                              
    0x3e7f5bc0 winlogon.exe        464    384 0x3ecf10c0 2010-06-16 15:25:18                              
    0x3eac6030 SearchProtocol     2448   1168 0x3ecf15c0 2010-06-16 23:30:52      2010-06-16 23:33:14     
    0x3eb10030 SearchFilterHo     1812   1168 0x3ecf1480 2010-06-16 23:31:02      2010-06-16 23:33:14 
    [snip]

If a process has previously terminated, the Time exited field will show the exit time. If you want to investigate a hidden process (such as displaying its DLLs), then you'll need physical offset of the `_EPROCESS` object, which is shown in the far left column. Almost all process-related plugins take a `--OFFSET` parameter so that you can work with hidden processes. 

## memmap

The memmap command shows you exactly which pages are memory resident, given a specific process DTB (or kernel DTB if you use this plugin on the Idle or System process). It shows you the virtual address of the page, the corresponding physical offset of the page, and the size of the page. The map information generated by this plugin comes from the underlying address space's get_available_addresses method. 

As of 2.1, the new column DumpFileOffset helps you correlate the output of memmap with the dump file produced by the [memdump](Command-Reference#memdump) plugin. For example, according to the output below, the page at virtual address 0x0000000000058000 in the System process's memory can be found at offset 0x00000000162ed000 of the win7_trial_64bit.raw file. After using [memdump](Command-Reference#memdump) to extract the addressable memory of the System process to an individual file, you can find this page at offset 0x8000. 

    $ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 memmap -p 4 
    Volatility Foundation Volatility Framework 2.4
    System pid:      4
    Virtual            Physical                         Size     DumpFileOffset
    ------------------ ------------------ ------------------ ------------------
    0x0000000000050000 0x0000000000cbc000             0x1000                0x0
    0x0000000000051000 0x0000000015ec6000             0x1000             0x1000
    0x0000000000052000 0x000000000f5e7000             0x1000             0x2000
    0x0000000000053000 0x0000000005e28000             0x1000             0x3000
    0x0000000000054000 0x0000000008b29000             0x1000             0x4000
    0x0000000000055000 0x00000000155b8000             0x1000             0x5000
    0x0000000000056000 0x000000000926e000             0x1000             0x6000
    0x0000000000057000 0x0000000002dac000             0x1000             0x7000
    0x0000000000058000 0x00000000162ed000             0x1000             0x8000
    [snip]