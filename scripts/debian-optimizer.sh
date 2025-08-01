#!/bin/bash
# https://github.com/hawshemi/Linux-Optimizer


# Green, Yellow & Red Messages.
green_msg() {
    tput setaf 2
    echo "[*] ----- $1"
    tput sgr0
}

yellow_msg() {
    tput setaf 3
    echo "[*] ----- $1"
    tput sgr0
}

red_msg() {
    tput setaf 1
    echo "[*] ----- $1"
    tput sgr0
}


# Declare Paths & Settings.
SYS_PATH="/etc/sysctl.conf"
PROF_PATH="/etc/profile"
SSH_PORT=""
SSH_PATH="/etc/ssh/sshd_config"
SWAP_PATH="/swapfile"
SWAP_SIZE=1G


# Root
check_if_running_as_root() {
    ## If you want to run as another user, please modify $EUID to be owned by this user
    if [[ "$EUID" -ne '0' ]]; then
      echo 
      red_msg 'Error: You must run this script as root!'
      echo 
      sleep 0.5
      exit 1
    fi
}


# Check Root
check_if_running_as_root
sleep 0.5


# Ask Reboot
ask_reboot() {
    yellow_msg 'Reboot now? (RECOMMENDED) (y/n)'
    echo 
    while true; do
        read choice
        echo 
        if [[ "$choice" == 'y' || "$choice" == 'Y' ]]; then
            sleep 0.5
            reboot
            exit 0
        fi
        if [[ "$choice" == 'n' || "$choice" == 'N' ]]; then
            break
        fi
    done
}


# Update & Upgrade & Remove & Clean
complete_update() {
    echo 
    yellow_msg 'Updating the System... (This can take a while.)'
    echo 
    sleep 0.5

    sudo apt -q update
    sudo apt -y upgrade
    sudo apt -y full-upgrade
    sudo apt -y autoremove
    sleep 0.5

    ## Again :D
    sudo apt -y -q autoclean
    sudo apt -y clean
    sudo apt -q update
    sudo apt -y upgrade
    sudo apt -y full-upgrade
    sudo apt -y autoremove --purge

    echo 
    green_msg 'System Updated & Cleaned Successfully.'
    echo 
    sleep 0.5
}


# Install XanMod Kernel
install_xanmod() {
    echo 
    yellow_msg 'Checking XanMod...'
    echo 
    sleep 0.5

    if uname -r | grep -q 'xanmod'; then
        green_msg 'XanMod is already installed.'
        echo 
        sleep 0.5
    else
        echo 
        yellow_msg 'XanMod not found. Installing XanMod Kernel...'
        echo 
        sleep 0.5

        ## Update, Upgrade & Install dependencies
        sudo apt update -q
        sudo apt upgrade -y
        sudo apt install wget curl gpg -y

        ## Check the CPU level
        cpu_level=$(awk -f - <<EOF
        BEGIN {
            while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1
            if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1
            if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2
            if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3
            if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4
            if (level > 0) { print level; exit level + 1 }
            exit 1
        }
EOF
        )

        if [ "$cpu_level" -ge 1 ] && [ "$cpu_level" -le 4 ]; then
            echo 
            yellow_msg "CPU Level: v$cpu_level"
            echo 

            ## Add the XanMod repository key
            # Define a temporary file for the GPG key
            tmp_keyring="/tmp/xanmod-archive-keyring.gpg"

            # Try downloading the GPG key from the XanMod link first
            if ! wget -qO $tmp_keyring https://dl.xanmod.org/archive.key || ! [ -s $tmp_keyring ]; then
                # If the first attempt fails, try the GitLab link
                if ! wget -qO $tmp_keyring https://gitlab.com/afrd.gpg || ! [ -s $tmp_keyring ]; then
                    echo "Both attempts to download the GPG key failed or the file was empty. Exiting."
                    exit 1
                fi
            fi

            # If we reach this point, it means we have a non-empty GPG file
            # Now dearmor the GPG key and move to the final location
            sudo gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg $tmp_keyring

            # Clean up the temporary file
            rm -f $tmp_keyring

            ## Add the XanMod repository
            echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
            
            ## Install XanMod
            sudo apt update -q && sudo apt install "linux-xanmod-x64v$cpu_level" -y

            ## Clean up
            sudo apt update -q
            sudo apt autoremove --purge -y
            
            echo 
            green_msg "XanMod Kernel Installed. Reboot to Apply the new Kernel."
            echo 
            sleep 1
        else
            echo 
            red_msg "Unsupported CPU. (Check the supported CPUs at xanmod.org)"
            echo 
            sleep 2
        fi
        
    fi
}


# Install useful packages
installations() {
    echo 
    yellow_msg 'Installing Useful Packages...'
    echo 
    sleep 0.5

    ## Networking packages
    sudo apt -q -y install apt-transport-https

    ## System utilities
    sudo apt -q -y install apt-utils bash-completion ca-certificates cron curl nano screen software-properties-common unzip wget zip git net-tools

    ## Programming and development tools
#    sudo apt -q -y install autoconf automake bash-completion build-essential git libtool make pkg-config python3 python3-pip

    ## Additional libraries and dependencies
#    sudo apt -q -y install bc binutils binutils-common binutils-x86-64-linux-gnu debian-keyring jq libsodium-dev libsqlite3-dev libssl-dev packagekit qrencode socat

    echo 
    green_msg 'Useful Packages Installed Succesfully.'
    echo 
    sleep 0.5
}


# Enable packages at server boot
enable_packages() {
    sudo systemctl enable cron
    echo 
    green_msg 'Packages Enabled Successfully.'
    echo
    sleep 0.5
}


# Swap Maker
swap_maker() {
    echo 
    yellow_msg 'Making SWAP Space...'
    echo 
    sleep 0.5

    ## Make Swap
    sudo fallocate -l $SWAP_SIZE $SWAP_PATH  ### Allocate size
    sudo chmod 600 $SWAP_PATH                ### Set proper permission
    sudo mkswap $SWAP_PATH                   ### Setup swap         
    sudo swapon $SWAP_PATH                   ### Enable swap
    echo "$SWAP_PATH   none    swap    sw    0   0" >> /etc/fstab ### Add to fstab
    echo 
    green_msg 'SWAP Created Successfully.'
    echo
    sleep 0.5
}


# SYSCTL Optimization
sysctl_optimizations() {
    ## Make a backup of the original sysctl.conf file
    cp $SYS_PATH /etc/sysctl.conf.bak

    echo 
    yellow_msg 'Default sysctl.conf file Saved. Directory: /etc/sysctl.conf.bak'
    echo 
    sleep 1

    echo 
    yellow_msg 'Optimizing the Network...'
    echo 
    sleep 0.5

    sed -i -e '/fs.file-max/d' \
        -e '/net.core.default_qdisc/d' \
        -e '/net.core.netdev_max_backlog/d' \
        -e '/net.core.optmem_max/d' \
        -e '/net.core.somaxconn/d' \
        -e '/net.core.rmem_max/d' \
        -e '/net.core.wmem_max/d' \
        -e '/net.core.rmem_default/d' \
        -e '/net.core.wmem_default/d' \
        -e '/net.ipv4.tcp_rmem/d' \
        -e '/net.ipv4.tcp_wmem/d' \
        -e '/net.ipv4.tcp_congestion_control/d' \
        -e '/net.ipv4.tcp_fastopen/d' \
        -e '/net.ipv4.tcp_fin_timeout/d' \
        -e '/net.ipv4.tcp_keepalive_time/d' \
        -e '/net.ipv4.tcp_keepalive_probes/d' \
        -e '/net.ipv4.tcp_keepalive_intvl/d' \
        -e '/net.ipv4.tcp_max_orphans/d' \
        -e '/net.ipv4.tcp_max_syn_backlog/d' \
        -e '/net.ipv4.tcp_max_tw_buckets/d' \
        -e '/net.ipv4.tcp_mem/d' \
        -e '/net.ipv4.tcp_mtu_probing/d' \
        -e '/net.ipv4.tcp_notsent_lowat/d' \
        -e '/net.ipv4.tcp_retries2/d' \
        -e '/net.ipv4.tcp_sack/d' \
        -e '/net.ipv4.tcp_dsack/d' \
        -e '/net.ipv4.tcp_slow_start_after_idle/d' \
        -e '/net.ipv4.tcp_window_scaling/d' \
        -e '/net.ipv4.tcp_adv_win_scale/d' \
        -e '/net.ipv4.tcp_ecn/d' \
        -e '/net.ipv4.tcp_ecn_fallback/d' \
        -e '/net.ipv4.tcp_syncookies/d' \
        -e '/net.ipv4.udp_mem/d' \
        -e '/net.ipv6.conf.all.disable_ipv6/d' \
        -e '/net.ipv6.conf.default.disable_ipv6/d' \
        -e '/net.ipv6.conf.lo.disable_ipv6/d' \
        -e '/net.unix.max_dgram_qlen/d' \
        -e '/vm.min_free_kbytes/d' \
        -e '/vm.swappiness/d' \
        -e '/vm.vfs_cache_pressure/d' \
        -e '/net.ipv4.conf.default.rp_filter/d' \
        -e '/net.ipv4.conf.all.rp_filter/d' \
        -e '/net.ipv4.conf.all.accept_source_route/d' \
        -e '/net.ipv4.conf.default.accept_source_route/d' \
        -e '/net.ipv4.neigh.default.gc_thresh1/d' \
        -e '/net.ipv4.neigh.default.gc_thresh2/d' \
        -e '/net.ipv4.neigh.default.gc_thresh3/d' \
        -e '/net.ipv4.neigh.default.gc_stale_time/d' \
        -e '/net.ipv4.conf.default.arp_announce/d' \
        -e '/net.ipv4.conf.lo.arp_announce/d' \
        -e '/net.ipv4.conf.all.arp_announce/d' \
        -e '/kernel.panic/d' \
        -e '/vm.dirty_ratio/d' \
        -e '/vm.overcommit_memory/d' \
        -e '/vm.overcommit_ratio/d' \
        -e '/^#/d' \
        -e '/^$/d' \
        "$SYS_PATH"


    ## Add new parameteres. Read More: https://github.com/hawshemi/Linux-Optimizer/blob/main/files/sysctl.conf

cat <<EOF >> "$SYS_PATH"


################################################################
################################################################


# /etc/sysctl.conf
# These parameters in this file will be added/updated to the sysctl.conf file.
# Read More: https://github.com/hawshemi/Linux-Optimizer/blob/main/files/sysctl.conf

net.core.rmem_max = 256960
net.core.rmem_default = 256960
net.core.wmem_max = 256960
net.core.wmem_default = 256960
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
# net.ipv4.tcp_mtu_probing = 1
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
# net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_sack = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_max_syn_backlog = 1024
net.ipv4.tcp_syn_retries = 6
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv4.tcp_congestion_control = cubic
# net.core.default_qdisc = fq_codel

################################################################
################################################################


EOF

    sudo sysctl -p
    
    echo 
    green_msg 'Network is Optimized.'
    echo 
    sleep 0.5
}


# 

# UFW Optimizations
ufw_optimizations() {
    echo
    yellow_msg 'Removing UFW...'
    echo 
    sleep 0.5
    ## Disable UFW
    sudo ufw disable
    
    ## Purge firewalld to install UFW.
    sudo apt -y purge ufw

    ## Install UFW if it isn't installed.
    sudo apt update -q
    sudo apt remove -y ufw
}


# Show the Menu
show_menu() {
    echo 
    yellow_msg 'Choose One Option: '
    echo 
    green_msg '1  - Apply Everything + XanMod Kernel. (RECOMMENDED)'
    echo
    green_msg '2  - Install XanMod Kernel.'
    echo 
    green_msg '3  - Complete Update + Useful Packages + Make SWAP + Optimize Network, SSH & System Limits + UFW'
    green_msg '4  - Complete Update + Make SWAP + Optimize Network, SSH & System Limits + UFW'
    green_msg '5  - Complete Update + Make SWAP + Optimize Network, SSH & System Limits'
    echo 
    green_msg '6  - Complete Update & Clean the OS.'
    green_msg '7  - Install Useful Packages.'
    green_msg '8  - Make SWAP (2Gb).'
    green_msg '9  - Optimize the Network, SSH & System Limits.'
    echo 
    green_msg '10 - Optimize the Network settings.'
    red_msg 'q - Exit.'
    echo 
}


# Choosing Program
main() {
    while true; do
        show_menu
        read -p 'Enter Your Choice: ' choice
        case $choice in
        1)
            apply_everything

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;

        2)
            complete_update
            sleep 0.5

            install_xanmod
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        3)
            complete_update
            sleep 0.5

            installations
            enable_packages
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5
            
            ask_reboot
            
            ;;
            
        4)
            complete_update
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5
          

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        5)
            complete_update
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        6)
            complete_update
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
            
        7)
            complete_update
            sleep 0.5

            installations
            enable_packages
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        8)
            swap_maker
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        9)
            sysctl_optimizations
            sleep 0.5
            
            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        10)
            sysctl_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ;;
        q)
            exit 0
            ;;

        *)
            red_msg 'Wrong input!'
            ;;
        esac
    done
}


# Apply Everything
apply_everything() {

    complete_update
    sleep 0.5

    install_xanmod
    sleep 0.5 

    installations
    enable_packages
    sleep 0.5

    swap_maker
    sleep 0.5

    sysctl_optimizations
    sleep 0.5

    remove_old_ssh_conf
    sleep 0.5

    update_sshd_conf
    sleep 0.5

    limits_optimizations
    sleep 0.5
    
    find_ssh_port
    ufw_optimizations
    sleep 0.5
}


main
