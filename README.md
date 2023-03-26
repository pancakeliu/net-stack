## Net Stack Quick Start

### DPDK Quick Start

```
# Install libnuma-dev
yum install numactl-devel          # on Centos
#sudo apt-get install libnuma-dev  # on Ubuntu

pip3 install pyelftools --upgrade
# Install python and modules for running DPDK python scripts
pip3 install pyelftools --upgrade # RedHat/Centos
sudo apt install python # On ubuntu
#sudo pkg install python # On FreeBSD
```

```
cd dpdk/
meson -Denable_kmods=true build
ninja -C build
ninja -C build install
```

```
# hold linux apt packages
apt-mark hold linux-image-`uname -r`
apt-mark hold linux-headers-`uname -r`
apt-mark hold linux-modules-extra-`uname -r`
```

```
# Set hugepage (Linux only)
# single-node system
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# or NUMA (Linux only)
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

# Using Hugepage with the DPDK (Linux only)
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Close ASLR; it is necessary in multiple process (Linux only)
echo 0 > /proc/sys/kernel/randomize_va_space

# Offload NIC
# For Linux:
modprobe uio
insmod /data/f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.ko
insmod /data/f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko carrier=on # carrier=on is necessary, otherwise need to be up `veth0` via `echo 1 > /sys/class/net/veth0/carrier`
python dpdk-devbind.py --status
ifconfig eth0 down
python dpdk-devbind.py --bind=igb_uio eth0 # assuming that use 10GE NIC and eth0

# For FreeBSD:
# Refer DPDK FreeBSD guide to set tunables in /boot/loader.conf
# Below is an example used for our testing machine
#echo "hw.nic_uio.bdfs=\"2:0:0\"" >> /boot/loader.conf
#echo "hw.contigmem.num_buffers=1" >> /boot/loader.conf
#echo "hw.contigmem.buffer_size=1073741824" >> /boot/loader.conf
#kldload contigmem
#kldload nic_uio
```

### Build Net Stack

```
make -j4
```