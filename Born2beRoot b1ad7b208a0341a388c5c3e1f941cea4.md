# Born2beRoot

## 🔑 Important keyword:

---

**Virtualization:** is a technology that separates functions from hardware. Virtualization uses software to simulate virtual hardware.that allows multiple **VMs** to run on a single machine. The physical machine is known as the host while the VMs running on it are called guests.

**VM - Virtual Machines:** is a virtual environment that works like a computer within a computer. It runs on an isolated partition of its host computer with its own CPU power, memory, operating system (such as Windows, Linux, macOS), and other resources. End users can run applications on VMs and use them as they normally would on their workstation.

**→** **VB - Virtual Box :**Is a *hypervisor*, Software for virtualizing x86 computing architecture (dev by Oracle). 

<aside>
📌 *hypervisor:* A hypervisor is software that creates and runs **[virtual machines (VMs)](https://www.citrix.com/content/citrix/en_us/solutions/vdi-and-daas/what-is-a-virtual-machine.html/)**, which are software emulations of a computing hardware environment. Sometimes called a virtual machine monitor (VMM), the hypervisor isolates the operating system and computing resources from the virtual machines and enables the creation and management of those VMs. These virtual machines simply, code operating in a server's memory space enable administrators to have a dedicated machine for every service they need to run.

</aside>

**OS - Operating System:** is a program that manages the computer hardware. it is an intermediary that acts between the computer hardware and the user. is a system software stored in the ROM and it’s the first program load by the boot.

<aside>
📌 boot*:* Bootstrap Program : the initial program that runs when a computer is powred up or rebooted.
→ stored in the ROM “second memory”
→ how load the OS and start execting that system.
→ locate and load into memory the OS kernel.

</aside>

**→ Debian:** also known as Debian *GNU*/Linux, is a Linux distribution composed of free and open-source software, Is a collection of software with a package management system, help to install, upgrade and remove software.

<aside>
📌 *GNU:* GNU is an extensive collection of free software, which can be used as an operating system or can be used in parts with other operating systems.

</aside>

**Linux: Linux is a Unix-like *kernel*.** Is an open source software, developed for the intel x86 architecture. The code used to create Linux is free and available to the public to view, edit, and—for users with the appropriate skills - to contribute to. 

<aside>
📌 ***kernel**:* The kernel is responsible for managing the systems resources and allocating them to applications.

</aside>

![linux0.1.png](Born2beRoot%20b1ad7b208a0341a388c5c3e1f941cea4/linux0.1.png)

## Hard disk Partitions

---

**Partitions:**

- **Partitioning** :Refers to the operation of dividing one physical storage device into several disk spaces inside the system.The physically divided space is called primary, and the logically divided space is called extended.
- **Partition** : An area that logically divides the hard disk capacity according to the user's needs. One disk can be divided into several partitions. A single physical space is logically divided and used through a file system called ***LVM***. Each storage space divided in this way is called a partition.
    
    <aside>
    📌 LVM - Logical Volume Management: **Uses a different concept. Storage space is managed by combining or pooling the capacity of the available drives.
    
    ![lvm.png](Born2beRoot%20b1ad7b208a0341a388c5c3e1f941cea4/lvm.png)
    
    </aside>
    
    Partitions are fixed and have a strong physical concept, and once the size is set, it is difficult to change or add, and the OS recognizes each partition as a separate disk.
    
- **Linux hard disk layout:**
    
    `/boot`:Directory as the boot loader configuration file and boot loader stages. It also stores data that is used before the kernel begins executing user-space programs.
    
    `/`: root
    
    `swap`:Is a file or partition that provides disk space used as virtual memory.
    
    `/home`:Directory contains user-specific configuration files, caches, application data and media files.
    
- **Mount:** Attaching a directory to the file system in order to access the partition and its file system is known as mounting.

**Partitions display & management command examples:**

```bash
lsblk #displaying partition information
vgs  #Display information about logical volumes
```

## Linux system management tools:

---

**APT - Advanced Package Tool:** 

Low-level package manager  ****is a free software interface that works with core libraries to handle the installation and removal of software on Debian.

**APT & Aptitude:**

**Aptitude:** A High-level package manager for Debian. It displays a list of software packages and allows the user to interactively pick packages to install or remove.

![Apt-get_install_mediawiki.png](Born2beRoot%20b1ad7b208a0341a388c5c3e1f941cea4/Apt-get_install_mediawiki.png)

![Aptitude.png](Born2beRoot%20b1ad7b208a0341a388c5c3e1f941cea4/Aptitude.png)

**Sudo - Super User DO:**

- Is a program for Unix-like computer operating systems;
- Allows a system administrator to give certain users (or groups of users) the ability to run some (or all) commands as root while logging all commands and arguments.
- Minimizing root privileges, using sudo is the basis for security.
    
    Installation:
    
    ```bash
    apt install sudo *#add user to sudo group*
    add username sudo
    visudo *#to change the configuration of sudo*
    
    sudo -l #*****************check sudo access*****************
    dpkg -l sudo #******************************check if the sudo is installed******************************
    ```
    
    Sudo configuration:
    
    ```bash
    #---------------- the bad password message -------------------------#
    Defaults	badpass_message="your password is wrong repaite again"
    #-------- block the usage of commend sudo whith unknown tty --------#
    Defaults	requiretty
    #-------- save all usage of command sudo in sudo.log file ----------#
    Defaults	log_input,log_output
    Defaults	iolog_dir="/var/log/sudo/"
    Defaults	logfile="/var/log/sudo/sudo.log"
    #- limited to 3 the attempts in the event of an incorrect password -#
    Defaults	passwd_tries=3
    #---------------- the paths that can be used by sudo ---------------#
    Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
    
    ```
    
    Sudo - Command:
    
    ```bash
    sudo adduser <username> #***********************add an user to the usre group***********************
    sudo groupadd <groupname> #******************************add an group****************************** 
    sudo usermod -aG <groupname> <username>
    sudo id <username> #***************************check the groups of this user***************************
    sudo deluser <username> *#Delete the user*
    sudo groupdel <groupname> *#Delete the group*
    getent group | grep <groupname to be found>
    cd /var/log/sudo/00/00 #check all command input output
    ```
    

**SSH - Secure SHell:**

Is access credential that is used in the SSH Protocol. In other words, it is a cryptographic network protocol that is used for transferring encrypted data over network. It allows you to connect to a server, or multiple servers, without having you to remember or enter your password for each system that is to login remotely from one system into another. this type of connection named key-based authentication.

<aside>
📌 *key-based authentication:* allows users to authenticate through a key-pair. The key pairs are two cryptographically secure keys for authenticating a client to a Secure Shell server.
The key pairs is :

  **Public key** : Everyone can see it, no need to protect it. (for encryption function)

**Private key** : Stays in computer, must be protected. (for decryption function)

Useful Links :

**Introduction:** [https://www.baeldung.com/cs/ssh-intro](https://www.baeldung.com/cs/ssh-intro)

****Tutorial:**** [https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)

</aside>

Installation :

```bash
apt install ssh 

**#go to the file /etc/ssh/sshd_config to change the defult port to 4242 and 
#root permition**
**
systemctl restart ssh 
**
service sshd status *#check status* 
```

**Password Policy:**

```bash
**#CHANGE THE PASSWORD TIME EXPIRATION**
nano /etc/login.defs 	*#The /etc/login.defs file defines the site-specific 
												#configuration for the shadow password suite.*

		| PASS_MAX_DAYS    30
		| PASS_MIN_DAYS    2
		| PASS_WARN_AGE    7

**#SET UP THE PASSWORD POLICY**
apt install libpam-pwquality -y ***# librery purpose is to provide common functions
																		#for password quality checking***
nano /etc/pam.d/common-password
		| retry=3 ucredit=-1 lcredit=-1 dcredit=-1 maxrepeat=3 difok=7 minlen=10 
		| usercheck=1 *#by default is equal to 1 so it's not important*
		| enforce_for_root

chage -W 7 -m 2 -M username ***#chage : change the number of days between password** 
															 **#changes and the date of the last change.***
															 #-W:warndays / -m:mindays / -M:maxdays
```

**UFW - Uncomplicated FireWall:** 

Is a frontend for managing *firewall* rules in Arch Linux, Debian, or Ubuntu. UFW is used through the command line (although it has GUIs available), and aims to make firewall configuration easy (or, uncomplicated).

<aside>
📌 *firewall:* A Linux firewall is defined as a solution or service that regulates, protects, and blocks network traffic as it passes to and from a Linux-based environment.

</aside>

```bash
apt install ufw -y *#instalation*
ufw allow 4242     # allowing connection by 4242 port
ufw enable         # active ufw state
```

**AppArmor**:

Is MAC(Mandatory Access Control) Framework style security extension for the Linux kernel, that allows the system administrator to restrict program’s capabilities, like network access, and the permission to read, write, or execute files.

```bash
aa-status #to show apparmor state
```

**→ Commande :**

Vue host info : `hostnamectl`

Check OS : `uname -a` or `cat /etc/os-release`

Check ID : `whoami`

Check user group : `id <username>`

Check the password setting : `cat /etc/shadow`

Check UFW: `systemctl status ufw`

Change the host name : `hostnamectl set-hostname new_host_name`

Check if sudo is installed :`$dpkg -l sudo`

to modifie crontab : `crontab -e`

Check the adresse of the user : `cat /etc/passwd`

## Monitoring.sh

```bash
#!/bin/bash
wall 	"#Architectur : $(uname -a)
	#CPU physical : $(nproc --all)
	#vCPU : $(cat /proc/cpuinfo | grep processor | wc -l)
	#Memory Usage :  $(free -m | grep Mem | awk '{printf("%d/%dMB (%.2f%%)\n", $3, $2, ($3/$2)*100)}')
	#Disk Usage : $(df --total -BM | grep total | awk '{printf"%d/%dGb (%d%%)\n", $3, $2/1024, $5}')
	#CPU load : $(top -ibn 1 | grep Cpu |tr -d "%C():[a-z]," | awk '{printf"%.2f%%\n", 100 - $4}')
	#Last boot : $(who -b | awk '{print $3" "$4}')
	#LVM use : $(if [ "$(lsblk | grep lvm | wc -l)" -gt 0 ] ; then printf "yes\n" ; else printf "no\n" ; fi)
	#Connection TCP : $(ss -t | grep ESTAB | wc -l) ESTABLISHID
	#User log : $(who | wc -l)
	#Network : $(echo -n "ID " && hostname -I | tr "\n" " " && echo -n "(" && cat /sys/class/net/enp0s3/address | tr "\n" ")" && echo)
	#Sudo : $(cat /var/log/sudo/sudo.log | grep COMMAND | wc -l) cmd"
'
#Architectur :
uname -a : #uname    -> print certain system information
						#uname -a -> all information;

#CPU physical : 
nproc --all : #nproc -> print the number of processing units available to the current process
								#--all -> print the number of installed processors

#vCPU : 
cat/proc/cpuinfo | grep processor | wc -l : 
						#cat/proc/cpuinfo -> display the all cpu information.
						#grep processor   -> display the line when the word "processe" exist.
						# wc    -> select which counts are printed //newline, word, character, byte...
						# wc -l -> print the newline counts.

#Memory Usage : 
free -m | grep Mem | awk '{printf("%d/%dMB (%.2f%%)\n" $3, $2, ($3/$2)*100)}'
						#free -m  -> display the memory usage (-m ; Megabyte).
						#grep Mem -> display the info from Mem (RAM memory).
						# awk     -> Awk is a scripting language used for manipulating data / 
													#and generating reports. The awk command programming language requires/ 
													#no compiling and allows the user to use variables, numeric functions,/
													#string functions, and logical operators.
													#$**number** -> the value in columns position(number)

#Disk Usage : 
df -BM --total | grep --total | awk '{printf"%d/%dGb (%d%%)\n", $3, $2/1024, $5}'
						#df -> (short for disk free), is used to display information related to file /
						#systems about total space and available space.

#CPU load : 
top -ibn 1 | grep Cpu |tr -d "%C():[a-z]," | awk '{printf"%.2f%%\n", 100 - $4}'
						#top -> program used to show the active Linux processes.
						#-ibn -> i:Idle-processe /b:Batch-mode operation /n:Number-of-iterations.
						#"%C():[a-z]," -> delete all this caracters from the output
						#100 - $4 			-> the $4 is the id "the idle cpu time" so 100 - $4 done the total of the cpu load.

#Last boot : 
who -b | awk '{print $3" "$4}'
						#who -b  -> who: print info about users who are currently logged in 
						#-b : time of last system boot.

#LVM use :
$(if [ "$(lsblk | grep lvm | wc -l)" -gt 0 ] ; then printf "yes\n" ; else printf "no\n" ; fi)
				#lsblk -> Display info about all partisions in the machine .

#Connection TCP : 
ss -t | grep ESTAB | wc -l printf " ESTABLISHID"
				#ss -> displays very detailed information about how a Linux machine is communicating/ 
				#with other machines, networks, and services; and information about network /
				#connections, networking protocol statistics, and Linux socket connections.
				#-t -> tcp; Display TCP sockets.

#User log :
who | cut -d " " -f 1 | sort -u | wc -l
				# cut -> to display some information by spesific ordes

#Network :
echo -n "ID " && hostname -I | tr "\n" " " && echo -n "(" && cat /sys/class/net/enp0s3/address | tr "\n" ")" && echo
				#hostname -I : to display the hostname name
				# I : display the hostname ID
				# /sys/class/net/enp0s3/address : the file whish the adresse is 
```

## Links:

**SSH:** [https://www.netburner.com/learn/introduction-to-the-ssh-protocol/](https://www.netburner.com/learn/introduction-to-the-ssh-protocol/)