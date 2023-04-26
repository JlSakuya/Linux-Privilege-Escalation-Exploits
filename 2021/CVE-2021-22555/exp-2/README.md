# CVE-2021-22555 pipe version

Using pipe-primitive  to exploit CVE-2021-22555, so no kaslr leak nor smap smep ktpi bypass is needed :)

(Q: What is pipe-primitive?  A: https://github.com/veritas501/pipe-primitive)

Tested on both Linux 4.15 and Linux 5.8

![](assets/tested_on_4.15.png)

![](assets/tested_on_5.8.png)
