# Linux Privilege Escalation Exploits

## Overview
The exploits collected in this project are for security learning and research purposes only.

## Kernel Vulnerabilities
The possible affected versions are just for the CVE not the exploits.

| CVE-ID                                                    | Possible affected versions                                                            |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| [CVE-2022-34918](./2022/CVE-2022-34918)                   | Linux kernel < 5.18.11                                                                |
| [CVE-2022-32250](./2022/CVE-2022-32250)                   | Linux kernel < 5.18.1                                                                 |
| [CVE-2022-27666](./2022/CVE-2022-27666)                   | Linux kernel < 5.17-rc8                                                               |
| [CVE-2022-25636](./2022/CVE-2022-25636)                   | Linux kernel 5.4-5.6.10                                                               |
| [CVE-2022-23222](./2022/CVE-2022-23222)                   | Linux kernel 5.8-5.16                                                                 |
| [CVE-2022-2639](./2022/CVE-2022-2639)                     | Linux kernel 3.13-5.18                                                                |
| [CVE-2022-2602](./2022/CVE-2022-2602)                     | Linux kernel < 6.1-rc1                                                                |
| [CVE-2022-2588](./2022/CVE-2022-2588)                     | Linux kernel < 5.19                                                                   |
| [CVE-2022-2586](./2022/CVE-2022-2586)                     | Linux kernel > 3.16-rc1                                                               |
| [CVE-2022-2585](./2022/CVE-2022-2585)                     | Linux kernel > 5.7-rc1                                                                |
| [CVE-2022-1015](./2022/CVE-2022-1015)                     | Linux kernel 5.12-5.17                                                                |
| [CVE-2022-0995](./2022/CVE-2022-0995)                     | Linux kernel 5.8-5.17-rc7                                                             |
| [CVE-2022-0847 (DirtyPipe)](./2022/CVE-2022-0847)         | Linux kernel 5.8-5.16.11                                                              |
| [CVE-2022-0185](./2022/CVE-2022-0185)                     | Linux kernel 5.1-rc1-5.17-rc1                                                         |
| [CVE-2021-43267](./2021/CVE-2021-43267)                   | Linux kernel 5.10-rc1-5.15                                                            |
| [CVE-2021-42008](./2021/CVE-2021-42008)                   | Linux kernel < 5.13.13                                                                |
| [CVE-2021-41073](./2021/CVE-2021-41073)                   | Linux kernel 5.10-5.14.6                                                              |
| [CVE-2021-31440](./2021/CVE-2021-31440)                   | Linux kernel 5.7-5.11.15                                                              |
| [CVE-2021-27365](./2021/CVE-2021-27365)                   | Linux kernel <= 5.11.3                                                                |
| [CVE-2021-22555](./2021/CVE-2021-22555)                   | Linux kernel 2.6.19-5.12-rc6                                                          |
| [CVE-2021-4154](./2021/CVE-2021-4154)                     | Linux kernel < 5.3.18                                                                 |
| [CVE-2021-3493](./2021/CVE-2021-3493)                     | Ubuntu 20.10、Ubuntu 20.04 LTS、Ubuntu 18.04 LTS、Ubuntu 16.04 LTS、Ubuntu 14.04 ESM  |
| [CVE-2021-3490](./2021/CVE-2021-3490)                     | Linux kernel < 5.13-rc4                                                               |
| [CVE-2020-27194](./2020/CVE-2020-27194)                   | Linux kernel 5.7-5.8.14                                                               |
| [CVE-2020-8835](./2020/CVE-2020-8835)                     | Linux kernel 5.4.7-5.4.29, 5.5-5.5.14, 5.6                                            |
| [CVE-2019-15666](./2019/CVE-2019-15666)                   | Linux kernel < 5.0.19                                                                 |
| [CVE-2019-13272](./2019/CVE-2019-13272)                   | Linux kernel 4.10-5.1.17                                                              |
| [CVE-2018-18955](./2018/CVE-2018-18955)                   | Linux kernel 4.15-4.19.2                                                              |
| [CVE-2018-17182](./2018/CVE-2018-17182)                   | Linux kernel 3.5-4.18.8                                                               |
| [CVE-2018-5333](./2018/CVE-2018-5333)                     | Linux kernel 4.4-4.14.13                                                              |
| [CVE-2017-1000253](./2017/CVE-2017-1000253)               | Linux kernel 3.2-4.13                                                                 |
| [CVE-2017-16995](./2017/CVE-2017-16995)                   | Linux kernel 4.4-4.14.8                                                               |
| [CVE-2017-16939](./2017/CVE-2017-16939)                   | Linux kernel < 4.13.11                                                                |
| [CVE-2017-11176](./2017/CVE-2017-11176)                   | Linux kernel <= 4.11.9                                                                |
| [CVE-2017-8890](./2017/CVE-2017-8890)                     | Linux kernel 2.5.69-4.11                                                              |
| [CVE-2017-7308](./2017/CVE-2017-7308)                     | Linux kernel 3.2-4.10.6                                                               |
| [CVE-2017-6074](./2017/CVE-2017-6074)                     | Linux kernel 2.6.18-4.9.11                                                            |
| [CVE-2017-5123](./2017/CVE-2017-5123)                     | Linux kernel 4.12-4.13                                                                |
| [CVE-2016-9793](./2016/CVE-2016-9793)                     | Linux kernel 3.11-4.8.14                                                              |
| [CVE-2016-8655](./2016/CVE-2016-8655)                     | Linux kernel 4.4.0-4.9                                                                |
| [CVE-2016-5195 (DirtyCow)](./2016/CVE-2016-5195)          | Linux kernel 2.6.22-4.8.3                                                             |
| [CVE-2016-4997](./2016/CVE-2016-4997)                     | Linux kernel <= 4.6.3                                                                 |
| [CVE-2016-4557](./2016/CVE-2016-4557)                     | Linux kernel 4.4-4.5.5                                                                |
| [CVE-2016-2384](./2016/CVE-2016-2384)                     | Linux kernel 3.0.0-4.4.8                                                              |
| [CVE-2016-0728 (pp_key)](./2016/CVE-2016-0728)            | Linux kernel 3.8.0-3.8.9, 3.9-3.13, 3.4.0-3.13.0, 3.8.5-3.8.9, 3.10.6, 3.9.6, 3.13.1  |
| [CVE-2015-8660](./2015/CVE-2015-8660)                     | Linux kernel 3.0.0-4.3.3                                                              |
| [CVE-2015-8550](./2015/CVE-2015-8550)                     | Linux kernel 4.19.65                                                                  |
| [CVE-2015-1328 (ofs)](./2015/CVE-2015-1328)               | Linux kernel 3.13, 3.16.0, 3.19.0                                                     |
| [CVE-2014-9322](./2014/CVE-2014-9322)                     | Linux kernel 3.0.1-3.17.5                                                             |
| [CVE-2014-4699](./2014/CVE-2014-4699)                     | Linux kernel 3.0.1-3.15.4                                                             |
| [CVE-2014-4014](./2014/CVE-2014-4014)                     | Linux kernel 3.0.1-3.14.8                                                             |
| [CVE-2014-3153](./2014/CVE-2014-3153)                     | Linux kernel 3.3.2-3.3.5, 3.0.1-3.0.5, 2.6.32-2.6.39, 2.6.4-2.6.9,3.2.2, 3.0.18       |
| [CVE-2014-0196 (rawmodePTY)](./2014/CVE-2014-0196)        | Linux kernel 2.6.31-2.6.39, 3.14, 3.15                                                |
| [CVE-2014-0038 (timeoutpwn)](./2014/CVE-2014-0038)        | Linux kernel 3.4-3.13, 3.4.0-3.8.0, 3.8.5, 3.8.6, 3.8.9, 3.9.0, 3.9.6, 3.10.0-3.13.0  |
| [CVE-2013-2094 (perf_swevent)](./2013/CVE-2013-2094)      | Linux kernel 3.0.0-3.0.6, 3.1.0, 3.2, 3.3, 3.4.0-3.4.9, 3.5, 3.6, 3.7, 3.8.0-3.8.9    |
| [CVE-2013-1959](./2013/CVE-2013-1959)                     | Linux kernel 3.0.1-3.8.9                                                              |
| [CVE-2013-1858 (clown-newuser)](./2013/CVE-2013-1858)     | Linux kernel 3.8-3.8.3                                                                |
| [CVE-2013-1763](./2013/CVE-2013-1763)                     | Linux kernel 3.3-3.8                                                                  |
| [CVE-2013-0268 (msr)](./2013/CVE-2013-0268)               | Linux kernel 2.6.18-2.6.39, 3.0.0-3.0.6, 3.1.0, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7.0, 3.7.6 |
| [CVE-2012-0056 (memodipper)](./2012/CVE-2012-0056)        | Linux kernel 2.6.39, 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0           |
| [CVE-2010-4347](./2010/CVE-2010-4347)                     | Linux kernel 2.6.0-2.6.36                                                             |
| [CVE-2010-4258 (full-nelson)](./2010/CVE-2010-4258)       | Linux kernel 2.6.31-2.6.37                                                            |
| [CVE-2010-4073 (half_nelson)](./2010/CVE-2010-4073)       | Linux kernel 2.6.0-2.6.36                                                             |
| [CVE-2010-3904 (rds)](./2010/CVE-2010-3904)               | Linux kernel 2.6.30-2.6.36                                                            |
| [CVE-2010-3301 (ptrace_kmod2)](./2010/CVE-2010-3301)      | Linux kernel 2.6.26-2.6.34                                                            |
| [CVE-2010-3081 (video4linux)](./2010/CVE-2010-3081)       | Linux kernel 2.6.0-2.6.33                                                             |
| [CVE-2010-2959 (can_bcm)](./2010/CVE-2010-2959)           | Linux kernel 2.6.18-2.6.36                                                            |
| [CVE-2010-1146 (reiserfs)](./2010/CVE-2010-1146)          | Linux kernel 2.6.18-2.6.34                                                            |
| [CVE-2009-3547 (pipe.c_32bit)](./2009/CVE-2009-3547)      | Linux kernel 2.4.4-2.4.37, 2.6.15-2.6.31                                              |
| [CVE-2009-2698 (udp_sendmsg_32bit)](./2009/CVE-2009-2698) | Linux kernel 2.6.1-2.6.19                                                             |
| [CVE-2009-2692 (sock_sendpage)](./2009/CVE-2009-2692)     | Linux kernel 2.4.4-2.4.37，2.6.0-2.6.30                                               |
| [CVE-2009-1337 (exit_notify)](./2009/CVE-2009-1337)       | Linux kernel 2.6.25-2.6.29                                                            |
| [CVE-2009-1185 (udev) ](./2009/CVE-2009-1185)             | Linux kernel 2.6.25-2.6.29                                                            |
| [CVE-2008-4210 (ftrex)](./2008/CVE-2008-4210)             | Linux kernel 2.6.11-2.6.22                                                            |
| [CVE-2008-0900](./2008/CVE-2008-0900)                     | Linux kernel 2.6.17-2.6.24.1                                                          |
| [CVE-2008-0600](./2008/CVE-2008-0600)                     | Linux kernel 2.6.23, 2.6.24                                                           |
| [CVE-2006-3626 (h00lyshit)](./2006/CVE-2006-3626)         | Linux kernel 2.6.8, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16            |
| [CVE-2006-2451 (raptor_prctl)](./2006/CVE-2006-2451)      | Linux kernel 2.6.13-2.6.17                                                            |
| [CVE-2005-1263](./2005/CVE-2005-1263)                     | Linux kernel 2.x.x-2.2.27-rc2, 2.4.x-2.4.31-pre1, 2.6.x-2.6.12-rc4                    |
| [CVE-2005-0736 (krad3)](./2005/CVE-2005-0736)             | Linux kernel 2.6.5, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11                               |
| [CVE-2004-1235 (elflbl)](./2004/CVE-2004-1235)            | Linux kernel 2.4.29                                                                   |
| [CVE-2004-0077 (mremap_pte) ](./2004/CVE-2004-0077)       | Linux kernel 2.4.20, 2.2.24, 2.4.25, 2.4.26, 2.4.27                                   |
| [CVE-N/A (caps_to_root)](./2004/caps_to_root)             | Linux kernel 2.6.34, 2.6.35, 2.6.36                                                   |

## User Vulnerabilities

| CVE-ID                                      | Possible affected versions      |
| ------------------------------------------- | ------------------------------- |
| [CVE-2021-4034](./2021/CVE-2021-4034)       | polkit、policykit-1 <=0.105-31  |
| [CVE-2021-3156](./2021/CVE-2021-3156)       | Sudo 1.8.2-31p2，Sudo 1.9.0-5p1 |
| [CVE-2019-7304](./2019/CVE-2019-7304)       | snapd < 2.37.1                  |
| [CVE-2018-1000001](./2018/CVE-2018-1000001) | glibc <= 2.26                   |
| [CVE-2017-1000367](./2017/CVE-2017-1000367) | Sudo 1.8.6p7-1.8.20             |
| [CVE-2017-7494](./2017/CVE-2017-7494)       | Samba 3.5.0-4.6.4/4.5.10/4.4.14 |
| [CVE-2015-7547](./2015/CVE-2015-7547)       | glibc < 2.9                     |
| [CVE-2014-5284](./2014/CVE-2014-5284)       | OSSEC 2.8                       |
| [CVE-2012-3524](./2012/CVE-2012-3524)       | libdbus <= 1.5.x                |

## Disclaimer
Please do not use it for illegal purposes, otherwise the serious consequences caused are not related to this project.

## References
+ [linux-kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)
+ [kernel-exploit-factory](https://github.com/bsauce/kernel-exploit-factory)
+ [kernel-exploits](https://github.com/lucyoa/kernel-exploits)
+ [LinuxEelvation](https://github.com/fei9747/LinuxEelvation)
+ [linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)