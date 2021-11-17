# Easy Kernel
## Challenge description

### Title: Easy kernel is still kernel right?
### Points worth: \~450
### Description

If you have never done kernel pwn before, check out this: https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/

nc ctf.k3rn3l4rmy.com 1003

## Downloadable part
https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/easy_kernel/easy_kernel.tar.gz

Also available in the git repo.

## Write-up

From the title it is clear this is going to be a kernel exploitation challenge. Since this was my first ever attempt to learn kernel exploitation, I started by reading the blog post mentioned in the description above, and hereon I will refer to it as "the blog post".

### Analyzing what's given to us

In the zip file, we are given a ton of things, so let's go over them one by one.

```bash
$ tar -tvf easy_kernel.tar.gz
-rw-rw-r-- seal/seal   9037184 2021-11-12 05:11 bzImage
drwxrwxr-x seal/seal         0 2021-11-12 05:11 fs/
               ...<fs files redacted>...
-rw-rw-r-- seal/seal   1528343 2021-11-12 05:11 initramfs.cpio.gz
-rwxrwxr-x seal/seal       273 2021-11-12 05:11 launch_pow.sh
-rwxrwxr-x seal/seal       343 2021-11-12 05:11 launch.sh
-rwxrwxr-x seal/seal       107 2021-11-12 05:11 rebuild_fs.sh
-rw-rw-r-- seal/seal    285344 2021-11-12 05:11 vuln.ko
```

Borrowing from the blog post:

1. `bzImage` is the compressed Linux kernel, which can be extracted to an ELF file called `vmlinux`.
2. The `fs` directory is the extracted filesystem of the device.
3. `initramfs.cpio.gz` is the filesystem of the device, compressed using `cpio` and `gzip`. This is the actual file that is used when emulating the machine.
4. The `launch_pow.sh` is a shell script which is run on the remote server and asks us to run a `hashcash` command so as to prevent DOS attacks. On successfull verification, it then executes the `launch.sh` script, which starts the `QEMU` emulator with the given kernel image and compressed filesystem.
5. `rebuild_fs.sh` is a script provided for our convenience, and it compresses the `fs` directory and stores it into the `initramfs.cpio.gz` file, allowing us to make changes to the filesystem.
6. And lastly, we have `vuln.ko`, which is a kernel module file. This is most probably the place where the vulnerability lies in.

After this, the first thing to do is extract the `vmlinux` ELF file from `bzImage` for debugging purposes and ROP gadgets. For this I used the `extract-image.sh` script that's included in this git repo, taken directly from the blog. 

```bash
$ ./extract-image.sh ./bzImage > vmlinux
```

We may require some gadgets in the next sections so it is better to run `ROPgadget` now since it'll take a lot of time.

```bash
$ ROPgadget --binary ./vmlinux > gadgets.txt
```

NOTE: Using `ropper` here failed for me. It always stopped at 96% loading and hanged there, and I have no clue as to why.

### Taking a look at the filesystem

In the fs directory, we see the usual directories along with a `flag.txt` containing a dummy flag for local exploitation purposes and the `vuln.ko` module, but the thing of interest here is the `init` script, as it gives us information about the target environment.

init:
```bash
mount -t proc none /proc
mount -t sysfs none /sys
mount -t 9p -o trans=virtio,version=9p2000.L,nosuid hostshare /home/ctf

insmod /vuln.ko

chown root /flag.txt
chmod 700 /flag.txt

exec su -l ctf
/bin/sh
```

This script mounts some necessary directories and also mounts a share named "hostshare" to /home/ctf, which will enable us to test our exploit without having to rebuild the filesystem and reboot the image. It then insertes the `vuln.ko` module into the kernel using `insmod` command, and makes the flag only readable by root.

One thing to do here is to comment out the `exec ...` command as when developing and debugging the exloit we will need some information which is only readable by the root user. After making the change we'll have to rebuild the filesystem, so `./rebuild_fs.sh`.

### launch.sh

The launch script is:

```bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

timeout --foreground 180 /usr/bin/qemu-system-x86_64 \
    -m 64M \
    -cpu kvm64,+smep,+smap \
    -kernel $SCRIPT_DIR/bzImage \
    -initrd $SCRIPT_DIR/initramfs.cpio.gz \
    -nographic \
    -monitor none \
    -append "console=ttyS0 kaslr quiet panic=1" \
    -no-reboot
```

This script runs the image for 180 seconds or 3 minutes, after which it kills `QEMU`, so we remove the `timeout`. Another important detail is that all protections are enabled, namely `stack canaries`, `smep`, `smap`, `kpti` and `kaslr`. I first disabled all these protections (excluding the canaries) and developed the first version of the exploit, then gradually added more mitigations, which is how I am going to walk through the writeup.

The modified script is:

```bash
/usr/bin/qemu-system-x86_64 \
    -m 64M \
    -cpu kvm64 \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -nographic \
    -monitor none \
    -append "console=ttyS0 nokaslr nopti nosmep nosmap quiet panic=1" \
    -no-reboot \
    -fsdev local,security_model=passthrough,id=fsdev0,path=./share -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare \
    -s
```

The `fsdev` and `device` options create a share named "hostshare" for the emulator which is just a folder named "share" in the current directory (make sure to create the folder). The `-s` flag makes the kernel available for debugging at localhost port 1234.
Running the `launch.sh` script now would launch the emulator, and we're good to start finding the vulnerability.


### Analyzing vuln.ko

Now we get to finding the vulnerability. I'm going to be using ghidra, but you can use any tool you want (binary ninja/IDA/hopper/etc). The entry point is not `main` but `init_func`, so we start by analyzing that.

![image](https://user-images.githubusercontent.com/70465008/142235511-2c958d9d-f535-4bb3-a506-34da11321fc0.png)

The function creates a device named "pwn_device" in `/proc`, and passes the options of fops. It then prints to the logs a success message using printk.

```bash
$ ls /proc | grep pwn
pwn_device
```

`fops` contains the options, a list of functions which are to be called when certain events occur.

![image](https://user-images.githubusercontent.com/70465008/142236174-5a8562d1-5663-4192-9d8b-89cd88ab8e46.png)

1. `sopen` -> called on opening pwn_device
2. `srelease` -> called on closing the device
3. `sread` -> called on reading from the device
4. `swrite` -> called on writing to the device
5. `sioctl` -> called when we call `ioctl` on the device

The `sopen` and `srelease` functions just print log messages, so we pay attention to the `sread`, `swrite` and `sioctl` functions.
