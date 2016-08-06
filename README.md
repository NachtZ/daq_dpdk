---
# Introduction
This is a project about dpdk module for daq.  
The DAQ version is v2.1.0. You can visit [Snort.org](https://snort.org/downloads/#snort-3.0) to download the origin version about daq and snort++.  
The daq module is overwrite from the module `daq_netmap.c`. And I also refer to [btw616's project](https://github.com/btw616/daq-dpdk) and [his mail](https://sourceforge.net/p/snort/mailman/message/35162409/) for how to use the new daq module in snort.  
Now the project version is v0.6. Now it support multithreading. One thread can only get packets from one port. I will test this module after my summer vacation because I don't have another computer to generate big flow now.
Now this module also has one problem. The dpdk args `-c` is still useless as the main controllor of thread is snort not daq. I'll try to slove this problem.
You can read my [dev_note](./dev_mote_zh.md) written in chinese.


---
# Install

You can read [btw616's mail](https://sourceforge.net/p/snort/mailman/message/35162409/). He show the path in snort2.9.8,dpdk16.04 and daq2.0.6.

The whole daq 2.1.0 has been pathed in the project. So you can download it.
## DPDK 
The dpdk path is:
```
diff --git a/mk/exec-env/linuxapp/rte.vars.mk b/mk/exec-env/linuxapp/rte.vars.mk
index 5fd7d85..847a3d0 100644
--- a/mk/exec-env/linuxapp/rte.vars.mk
+++ b/mk/exec-env/linuxapp/rte.vars.mk
@@ -41,6 +41,8 @@
 #
 ifeq ($(CONFIG_RTE_BUILD_SHARED_LIB),y)
 EXECENV_CFLAGS  = -pthread -fPIC
+else ifeq ($(CONFIG_RTE_BUILD_FPIC),y)
+EXECENV_CFLAGS  = -pthread -fPIC
 else
 EXECENV_CFLAGS  = -pthread
 endif
```

then 
```shell
$ make config T=x86_64-native-linuxapp-gcc
$ echo 'CONFIG_RTE_BUILD_FPIC=y' >> build/.config
$ echo 'CONFIG_RTE_BUILD_COMBINE_LIBS=y' >> build/.config
$ make
<... setup dpdk ...>
```
## DAQ
download this project.
```
$ aclocal
$ autoconf
$ autoheader
$ automake -a
$ ./configure --with-dpdk-includes=$RTE_SDK/$RTE_TARGET/include --with-dpdk-libraries=$RTE_SDK/$RTE_TARGET/lib
$ make && sudo make install
```

## Snort
The version now is `snort-3.0.0-a4-201`.
You can install snort by following it's `README`.
Then after`./configure`.  
edit it's `./src/Makefile`
eidt line 620 to :
```
	$(AM_V_CXXLD)$(snort_LINK) $(snort_OBJECTS) $(snort_LDADD) $(LIBS) -Wl,--whole-archive,-ldpdk,--no-whole-archive
```

then continue the install.

---
# Usage
```
sudo snort --daq-dir /usr/local/lib/daq/ --daq dpdk --daq-var dpdk_args="-c 3" -i dpdk0:dpdk1 -c /usr/local/etc/snort/snort.lua
```
