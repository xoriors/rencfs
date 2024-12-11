# Testing

We'd appreciate it if you could help test the app. For now, the filesystem mounting works only on Linux, so the cleanest way is to test on Linux.

Here are some ways you can do it.

## Testing in VSCode

If you want to test quickly and have just VSCode installed locally.

### First setup

1. Install VSCode based on your OS
2. Open the [repo](https://github.com/radumarias/rencfs)
3. Press `Code` button  
  ![image](https://github.com/user-attachments/assets/7c0e8872-fe1f-44b9-a833-2586ade4f618)
4. Create codespace on main  
  ![image](https://github.com/user-attachments/assets/5fee55f6-ef54-427c-b790-c135312d3355)
5. This will create the container on GitHub. If it asks you to setup config, select the minimum possible CPU and RAM
6. Start it and leave it to finish
7. Go back to the repo root. You can close the current tab
8. Press `Code` button
  ![image](https://github.com/user-attachments/assets/0baec7da-cbbd-4186-a82b-887e18c0c85d)
9. Press ```...``` right to the instance in the list
  ![image](https://github.com/user-attachments/assets/c621c258-009d-46bf-adb7-f81a3d7131f6)
10. Press `Open in Visual Studio Code`
11. Allow it to finish
12. Open a terminal in VSCode from the menu `Terminal -> New Terminal`
13. If you start it for the first time, install Rust and create a `tmp` folder, which we will use to copy files from our machine, by typing these in terminal:
  ```bash
  mkdir tmp
  
  apt-get update && apt-get install fuse3
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  mkdir mnt && mkdir data
  ```
  Press enter on Rust installation, accepting all defaults

### Each resume and after Fist setup

Do steps 2, 8, 9, 10, 11, 12.

1. Type this in terminal, which will fetch the changes from the repo (if there are conflicts, accept Theirs):
  ```bash
  git pull
  cargo run --release -- mount -m mnt -d data
  ```
2. Input a password and confirm it the first time
3. Copy test files from your machine to `tmp` folder in `VSCode`, by `Ctrl + C / Ctrl + V` or by Drag and Drop
4. Copy files and folders from `tmp` to `mnt` and do all kinds of operations on `nnt` folder
5. Make sure files were copied successfully by right-clicking a file and then `Download...` and save it to local machine
6. Make sure files open correctly
7. Do all kinds of operations in `mnt` folder and make sure they are ok

## Testing on Linux

TODO

## Testing on macOS

TODO

## Testing on Windows

TODO
