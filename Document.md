# Certified Kubernetes Security Specialist

## Understanding the Kubernetes Attack Surface
+ The Attack
    + Pick a local Domain
    + Find the IP using Ping
    + Find Ports open against that IP usin nmap
    + if Docker is exposed for that IP then connect with Docker
    + Get the privileged access
+ The 4C's of Cloud Native Security
    + Cloud
    + Clusters
    + Containers
    + Code

### Tools:
----
#### nmap : utility for network discovery and security auditing
    ```sh
    #nmap <domain-name>
    #nmap -a <domain-name>
    #namp -iL <file-name-containting-list-of-domains-or-ips>
    ```
----
#### iptables : netfilters is a framwork on linux kernel whereas iptables uses the netfilters.
+ TABLES
     + FILTERS
        + INPUT
        + OUTPUT
        + FORWARD
     + NAT
     + MANGLE
+ Default Firewall
     + Ubuntu - UFW (Uncomplicated Firewall)
     + Centos - Firewalld
    ```sh
    #apt install iptables
    #iptables -L
    #/sbin/iptables-save
    #apt install net-tools
    #apt install apache2
    #systemctl status apache2
    #iptables -I INPUT -s 192.168.29.144 -p tcp --dport 80 -j DROP
    #iptables -I INPUT -p tcp --dport 80 -j DROP
    #iptables -F
    #iptables -D INPUT 1
    ```

Parameter    | Parameter Details
-------------| ----------------------------
-I           | Add rule at the top
-A           | Add rule at the end - Append
-s           | Source IP's
-j           | target (ACCEPT/REJECT/DROP)
-p           | protocol (tcp/udp)
--dport      | port-number 

#### ufw
```sh
#PENDING
```

#### firewalld
```sh
#PENDING
```

## Cluster Security and Hardening

+ ### Security Benchmark
    + Physical Device (USB)
    + Access (root account disabled, user with sudo privileges)
    + Network (iptables & Firewall enabled with required port enabled)
    + Service (Deploy and ebaled only required services)
    + Filesystem (required Permission given)
    + Auditing
    + Logging

+ ### What is CIS Benchmark ?
    + Center for Internet Security
    + CIS published the best practises document
    + CIS also provide tool to validate the env as per the best practises
        + CIS-CAT Lite
        + CIS-CAT Pro
    + Report are generated in HTML format
        ```sh
        #cd Assessor
        #sh ./Assessor-CLI.sh -i -rd /var/www/html/ -nts -rp index
        ```
+ ### CIS Benchmark - Kubernetes
    + kube-bench tool from Aqua Security
        ```sh
        #curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz -o kube-bench_0.4.0_linux_amd64.tar.gz
        
        #tar -xvf kube-bench_0.4.0_linux_amd64.tar.gz

        # ./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml 
        ```
+ ### Kubernetes Security Primitives:
    + Secure Host
        + Password Based Authentication Disabled
        + SSh Key Based Authentication
    + kube-apiserver
        + Who can access - Authentication
            + Files - Username and Password
            + Files - Username and Token
            + Certificate
            + LDAP
            + Service Account
                + K8s 1.22
                    ![KEP-1205](KEP-1205.png "KEP-1205")
                    ![KEP-1205](KEP-1205-TokenRequestAPI.png "KEP-1205")
                + K8s 1.24
                    ![KEP-2799](KEP-2799.png "KEP-2799")
                    ```sh
                    #kubectl create serviceaccount dashboard-sa
                    ** Attached the role/clusterrole and rolebinding/clusterrolebinding to this service account as per requirement
                    #kubectl get serviceaccount
                    ** Path - /var/run/secrets/kubernetes.io/serviceaccount
                    ```
        + What they can do - Authorization
            + RBAC
                + Create role, rolebinding, clusterrole and clusterrolebinding
                ```sh
                #kubectl auth can-i list pods --as <user> -n <namespace>
                #kubectl auth can-i list pods --as=system:serviceaccount:<serviceaccount>:<namespace> -n niam
                #kubectl api-resources --namespaced=true
                #kubectl api-resources --namespaced=false
                ```
                
            + ABAC
            + Node
            + Webhook
        + TLS
            + Cetificates:
                + Server Certificates
                + Client Certificates
                + CA Certificates
            + Encryption:
                + Symmetric Encryption (Single Key to Encrypt the data and Decrypt the Data)
                + Asymmetric Encryption (Pair of Key - Public and Private, one for encryption and another for decyption)
            + Public Key Infrastructure:
                + Public Key
                    + *.crt
                    + *.pem
                + Private Key
                    + *.key
                    + *-key.pem
            + Commands:
                ```sh
                #openssl x509 -in <crt-file> -noout -text
                ```
            + Certificate API:
                ```sh
                #kubectl get csr
                #kubectl certificate approve <csr-name>
                #kubectl certificate deny <csr-name>
                #kubectl delete csr <csr-name>
                ```

        + Network Policy

+ ### Kubeconfig:
    ```sh
    #kubectl config view
    #kubectl config use-context <user>@<cluster>
    #kubectl config -h
    ```

+ ### API Groups:
    + core
    + named

+ ### Kubelet Security:
    + Ports
        + 10250 - Serves API that allow full access
        + 10255 - Serves API that allow unauthenticated read-only access
    + Parameters:
        ```sh
        #--anonymous-auth=false
        #--authorization-mode=Webhook
        #--read-only-port=0
        ```
    + Two Type of Authentication:
        + Certificate (x509)
        + API Bearer Tokens

+ ### kubectl proxy & port forward:
    ```sh
    KUBECTL PROXY - Opens proxy port to API server
    #kubectl proxy ----> this will expose kube-api-server api on 127.0.0.1:8001

    PORT FORWARD -Opens port to target deployment pods
    #kubectl port-forward service/nginx 28080:80
    ```

+ ### Kubernetes Dashboard - Authentication:
    + Token
    + kubeconfig file

+ ### Verify Platform Binaries before Deploying
    + Verify the checksum
        ```sh
        #sha512sum <filename>
        ```

+ ### Kubernetes Releases:
    + VERSION - MAJOR.MINOR.PATCH
    + Cluster Version for Upgrade:
        + kube-apiserver (x)
        + kube-scheduler and kube-controller-manager (x or x-1)
        + kubelet and kube-proxy (x or x-1 or x-2)
        + kubectl (x+1 or x or x-1)  
    + Upgrade Process
        + Master Nodes
            ```sh
            #Update packages --> #apt update
            #find the kubeadm next update version
            #Upgrade kubeadm
            #kubeadm upgrade plan
            #kubeadm upgrade apply

            For the Other Master Nodes :
            #kubeadm upgrade node

            Then on each control node
            #kubectl drain node
            #Upgrade kubelet and kubectl
            #kubectl uncordon node
            ```
        + Worker Nodes
            ```sh
            #Update packages --> #apt update
            #Upgrade kubeadm
            #kubeadm upgrade node
            #kubectl drain node  --> This will run from control node
            #Upgrade kubelet and kubectl
            #kubectl uncordon node   --> This will run from control node          
            ```

+ ### Kubernetes Network Policies:
    + PolicyType:
        + Ingress
        + Egress
    + Make sure Network Solution (CNI Plugin) should support Network Policy

+ ### Ingress:
   
    ```sh
    #kubectl create ingress <ingress-name> --rule="host/path=service:port"
    #kubectl create ingress ingress-test --rule="wear.my-online-store.com/wear*=wear-service:80"
    ```

+ ### Docker Service Configuration:
    + Background - #systemtctl start docker
    + Foreground - #dockerd or #dockerd --debug 
    + When docker daemon runs it listen on Unix Socket (Path /var/run/docker.sock).If we want to access the docker CLI from remote machine then we need to expose this on tcp port, Extermely carefull if exposing on tcp port:
    ```sh
    #dockerd debug --host=tcp://<IP>:2375
    ```
    + Also enable tls encryoption in Docker. And these configuration can be moved to /etc/docker/daemon.json
        ```sh
    #dockerd debug --host=tcp://<IP>:2376 --tls=true --tlscert=server.pem --tlskey=serverkey.pem --tlsverify=true --tlscacert=caserver.pem
    ```

## Security Hardening

+ ### Minimize host OS Footprint
+ ### Limit Node Access
    + Do not provide direct access on servers over Internet, access the cluster via dedicated channel or via VPN.
    + Enable Firewall to given required source network address
    + Four Types of Accounts :
        + User Account (abhishek, swati)
        + Superuser Account (root)
        + System Accounts (ssh, mail)
        + Service Accounts (nginx, http)
        ```sh
        SAMPLE COMMANDS:
        #id
        #whoami
        #last
        Disable the User login
        #usermod -s /bin/nologin abhishek
        Delete the User
        #userdel abhishek
        Remove User from Group
        #deluser abhishek admin 
        ```
    + Access Control Files:
        ```sh
        #/etc/passwd
        #/etc/shadow
        #/etc/group
        ```

+ ### SSH Hardening
    ```sh
    #ssh-keygen -t rsa
    #ssh-copy-id <user>@<ip>
    ```
    + Update the sshd_config file from /etc/ssh path
    ```sh
    cat /etc/ssh/sshd_config
    PermitRootLogin no
    PasswordlessAuthentication no

    #systemtctl restart sshd
    ```

+ ### Privilege Escalation in Linux
    ```sh
    cat /etc/sudoers
    abhishek ALL=(ALL:ALL) ALL
    %developer ALL=(ALL:ALL) ALL

    #usermod -s /usr/sbin/nologin root
    ```
+ ### Remove Obsolete Packages and Services
    ```sh
    FIND THE SERVICES INSTALLED
    #systemctl list-units --type service
    #apt list --installed
    STOP DISABLE THE SERVICE
    #systemctl stop <service>
    #systemctl disable <service>
    REMOVE THE SERVICE
    #apt remove <service>
    ```
+ ### Restrict Kernel Modules
    ```sh
    #modprobe pcspker --> To add module
    #lsmod  --> List all kernel module
    BLACKLIST THE MODULE
    #cat /etc/modeprobe.d/blacklist.conf
    blacklist sctp
    blacklist dccp
    #shutdown -r now
    #lsmod | grep "sctp\|dccp"
    ```

+ ### Identify and disable open ports
    ```sh
    #netstat -an | grep -w LISTEN
    #cat /etc/services | grep -w 80
    ```

+ ### Minimize IAM roles
    + Do not use root account for services creation
    + Create Users
    + Always prefer IAM role
+ ### UFW(Uncomplicated Firewall) Firewall Basic
    + Network Security
        + External Firewall - Cisco ASA, Juniper NGFW, Barracuda NGFW, Fortinet
        + Alternative Option to apply these rule in indiviual servers using iptables, firewalld, ufw.
    ```sh
    #apt-get update
    #apt-get install ufw
    #systemctl enable ufw
    #systemctl start ufw
    #ufw status
    #ufw status numbered
    Allow port 1000 to 2000
    #ufw allow 1000:2000/tcp
    #ufw default allow outgoing
    #ufw default deny incoming
    #ufw allow from 172.16.238.5 to any port 22 proto tcp
    #ufw allow from 172.16.238.5 to any port 80 proto tcp
    #ufw allow from 172.16.238.6 to any port 22 proto tcp
    #ufw deny 80
    #ufw delete deny 80
    Delete Based on Line Number:
    #ufw delete 5
    #ufw enable
    #ufw status
    #ufw reset
    #ufw disable
    ```
+ ### Linux SYSCALLS
    + Proccess(User space) uses "System Calls" to Kernel(Kernel space) for accessing the memory, cpu and devices.
        ```sh
        #touch 1.txt
        To find the syscall use strace
        #which strace
        #strace touch 1.txt
        #strace -c touch 1.txt
        
        syscall name, argument passed to the syscall and retrun status.

        Check the syscalls for running process first get the PID and then check strace
        #pidof etcd
        #strace -p <pid>
        ```
    + Aquasec Tracee
        + To trace the syscalls on containers
        + EBPF (Extended Berkeley Packet Filter) to trace te syscall at runtime
        ```sh
        For all the list command syscalls:
        #docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src/:/usr/src/:ro -v /tmp/tracee:/tmp/tracee auqasec/tracee:0.4.0 --trace comm=ls
        For all the new process syscalls:
        #docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src/:/usr/src/:ro -v /tmp/tracee:/tmp/tracee auqasec/tracee:0.4.0 --trace pid=new
        For all the new containers syscalls:
        #docker run --name tracee --rm --privileged --pid=host -v /lib/modules/:/lib/modules/:ro -v /usr/src/:/usr/src/:ro -v /tmp/tracee:/tmp/tracee auqasec/tracee:0.4.0 --trace container=new
        Run new container a see the syscalls:
        #docker run ubuntu echo Hi        
        ```
+ ### Restricting syscalls using seccomp
    + Vulnerability named - Dirty Cow
    + Seccomp - Secure Computing
        + Check whether system supported the Seccomp:
        ```sh
        #grep -i seccomp /boot/config-$(uname -r)
        #docker run docker/whalesay cowsay hello!
        #docker run -it --rm docker/whalesay /bin/sh
        CHANGE THE SYSTEM TIME
        #date -s "10 APR 2023 22:00:00"
        #ps -ef
        #grep Seccomp /proc/1/status
        ```
        #docker run r.j3ss.co/amicontained amicontained
        ![SECCOMP_DOCKER](SECCOMP_DOCKER.png "SECCOMP_DOCKER")
        #kubectl run amicontained  --image jess/amicontained amicontained -- amicontained
        ![SECCOMP_K8S](SECCOMP_K8S.png "SECCOMP_K8S")
        ![SECCOMP_K8S_Enabled](SECCOMP_K8S_enabled.png "SECCOMP_K8S_enabled")
    + Seccomp Mode
        + Mode 0 - DISABLED
        + Mode 1 - STRICT (READ, WRITE, EXIT and CIGARETTE)
        + Mode 2 - FILTERED

+ ### Implement Seccomp in Kubernetes
    + CUSTOMER PROFILE
    ```
    apiVersion: v1
    kind: Pod
    metadata:
         name: audit-nginx
    spec:
        securityContext:
            seccompProfile:
                type: Localhost
                localhostProfile: /var/lib/kubelet/seccomp/profiles/audit.json
        containers:
        - image: nginx
            name: nginx
    ```

+ ### Kernel Hardening Tools - AppArmor  
    + Limiting the secomp to a particular directoy. i.e. mkdir to /opt path will not work. Fine-grain control over the process.
        ```sh
        #systemctl status apparmor
        #cat /sys/module/apparmor/parameters/enabled
        Y
        #cat /sys/kernel/security/apparmor/profiles
        #aa-status

        #apt-get install apparmor-utils
        #aa-genprof /home/abhishek/Downloads/add_data.sh
        #aa-status
        #cat /etc/apparmor.d/root.add_data.sh
        #apparmor_parser /etc/apparmor.d/root.add_data.sh
        ```
    + AppArmor Profiles
        + enforce
        + complain
        + unconfined

    + Linux Capabilities:
        + CAP_CHOWN: Perform chown() operations.
        + CAP_DAC_OVERRIDE: Bypass file read, write, and execute permission checks.
        + CAP_DAC_READ_SEARCH: Bypass file read permission checks and directory read and execute permission checks.
        + CAP_FOWNER: Bypass permission checks for operations that normally require the file's owner ID to match the user's effective ID.
        + CAP_NET_RAW: Use RAW and PACKET sockets.
        + CAP_SYS_ADMIN: Perform a range of administrative operations.
        + CAP_SYS_CHROOT: Use chroot().
        + CAP_SETUID: Set arbitrary user IDs.
        + CAP_SETGID: Set arbitrary group IDs.
        + CAP_AUDIT_WRITE: Write records to kernel's audit subsystem.
        + CAP_KILL: Bypass permission checks for sending signals.
        + CAP_NET_BIND_SERVICE: Bind a socket to internet domain privileged ports (<1024).
        + CAP_SYS_PTRACE: Trace arbitrary processes using ptrace.
        + CAP_SYS_MODULE: Load and unload kernel modules.
        + CAP_SYS_NICE: Raise process nice value.
        + CAP_SYS_RESOURCE: Override resource limits.
        + CAP_SYS_TIME: Set system clock.
        + CAP_SYS_TTY_CONFIG: Use TIOCSTI ioctl to push characters into the terminal input queue.
        + CAP_AUDIT_CONTROL: Enable and disable kernel auditing.
        + CAP_MAC_ADMIN: Override Mandatory Access Control (MAC) system policies.
        + CAP_MAC_OVERRIDE: Override MAC access on files.
        ```sh
        Inside Container
        #ps -ef
        #getpcaps <pid>
        ```

## Minimizing Microservice Vulnerabilities
## Supply Chain Security
## Logging, Monitoring and Runtime Security
