---
# Introduction
This is a project about dpdk module for daq.  
The DAQ version is v2.1.0. You can visit [Snort.org](https://snort.org/downloads/#snort-3.0) to download the origin version about daq and snort++.  
The daq module is overwrite from the module `daq_netmap.c`. And I also refer to [btw616's project](https://github.com/btw616/daq-dpdk) and [his mail](https://sourceforge.net/p/snort/mailman/message/35162409/) for how to use the new daq module in snort.  
Now the project version is v1.0. Now it support multithreading. One thread can only get packets from one port. I have tested this module and got a good performance now.
Now this module also has one problem. The dpdk args `-c` is still useless as the main controllor of thread is snort not daq. I'll try to slove this problem.
You can read my [dev_note](./dev_note_zh.md) written in chinese.


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
You can install snort by following it's [README](https://github.com/snortadmin/snort3/blob/master/README.md).
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
sudo snort --daq-dir /usr/local/lib/daq/ --daq dpdk --daq-var dpdk_args="-c 1" -i dpdk0:dpdk1 -c /usr/local/etc/snort/snort.lua -z 2
```
`--daq-dir` : the path of daq lib.  
`--daq dpdk`: tell snort to use dpdk module.  
`--daq-var dpdk_args="-c 1"`: the argument of dpdk. You have no need to edit it, if you want to use miti-trhead. you should use `-z` option.  
`-i dpdk0:dpdk1`: choose the interface of dpdk. Start from dpdk0.  
`-z 2`:max number of packet thread. One packet thread can only and must have one NIC.  

---
# Performance

I have test the performance of this module by using inline mode.
```
snort --daq-dir /usr/local/lib/daq/ -Q --daq dpdk --daq-var dpdk_args="-c f" -i dpdk0:dpdk1 --bpf 'not ip' -z 5
```

I use Spirent Test Center to test the inline mode of Snort. Link two ports of the Test Center(called port0 and port1) and my server(called port2 and port3).
port0 send packets to port2, and the snort will transmit the traffics from port3 to port1. The Test Center will show the rate and numbers of packets.


```
 Spirent Port0   <-------------->   My Server Port2
	  ↑                                  ↑
	  |                                  |
	  |                                  |
	  ↓                                  ↓
 Spirent Port1   <-------------->   My Server Port3
```

Here shows my result.

Speed(Gbps)|Packet reception rate(%)
---|---
4.46Gbps|100%
5.00Gbps|100%
5.49Gbps|100%
5.97Gbps|100%
6.49Gbps|100%
6.98Gbps|100%
7.49Gpbs|100%
7.797Gbps|100%
8.41Gbps|100%
8.93Gbps|100%
9.49Gbps|100%
9.74Gbps|100%
10.00Gbps|99.9999%
