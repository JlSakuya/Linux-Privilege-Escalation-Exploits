<h1 align='center'>CVE-2018-18955</h1>

Linux local root exploit.

Wrapper for Jann Horn's
[exploit](https://bugs.chromium.org/p/project-zero/issues/detail?id=1712) for
[CVE-2018-18955](https://nvd.nist.gov/vuln/detail/CVE-2018-18955), forked from
[kernel-exploits](https://github.com/bcoles/kernel-exploits).

In the Linux  kernel 4.15.x through 4.19.x  before 4.19.2, `map_write()`
in  `kernel/user_namespace.c`  allows  privilege escalation  because  it
mishandles nested user namespaces with more  than 5 UID or GID ranges. A
user who  has `CAP_SYS_ADMIN` in  an affected user namespace  can bypass
access controls on  resources outside the namespace,  as demonstrated by
reading `/etc/shadow`.  This occurs  because an ID  transformation takes
place properly  for the namespaced-to-kernel  direction but not  for the
kernel-to-namespaced direction.

### Usage

Simply download  one of the  release archives and  run one of  the shell
scripts depending on the targeted exploitation technique.

### Disclaimer

Running unathorized attacks to public or private servers is illegal. The
content  of this  repository is  for  educational purposes  only and  no
responsibility will be  taken by the authors  in case of ill  use of the
provided material.
