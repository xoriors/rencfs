```mermaid
sequenceDiagram 
    actor user
    participant rencfs as rencfs-cli
    participant filesystem

    user -->> rencfs : --data-dir /home/user/data <br> --mount-point /home/user/mnt
    rencfs -->> user : password ?
    user -->> rencfs : 1234
    rencfs -->> filesystem : create /home/user/data <br> create /home/user/mnt
    create participant /home/user/mnt 
    filesystem -->> /home/user/mnt : 
    create participant /home/user/data
    filesystem -->> /home/user/data : 
    filesystem -->> rencfs : 
    rencfs -->> filesystem : mount /home/user/data <br> under /home/user/mnt
    filesystem -->> rencfs : 
    user -->> /home/user/mnt : create file
    /home/user/mnt -->> rencfs : create file
    rencfs -->> rencfs : create encrypted file and metadata
    rencfs -->> /home/user/data : store encrypted file and medatada
    /home/user/data -->> rencfs : 
    rencfs -->> /home/user/mnt : file created 
    /home/user/mnt -->> user : file created
    user -->> rencfs : ctrl+c
    rencfs -->> filesystem : unmount /home/user/data <br> from /home/user/mnt
    filesystem--x/home/user/mnt : 
    filesystem--x/home/user/data : 
    filesystem -->> rencfs : 
    rencfs --x rencfs : exit
```

