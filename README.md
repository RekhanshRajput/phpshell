# SNIPER

**SNIPER** is a modern dark-themed PHP web shell and advanced file manager with an interactive terminal, real-time system monitoring, and optional elevated (root/sudo) file operations.

> ⚠️ **Disclaimer**  
> This project is created **strictly for educational purposes, authorized security testing, and local use on systems you own or have explicit written permission to access**.  
> Unauthorized use of this tool on any system is illegal. The author takes no responsibility for any misuse, damage, or legal consequences.

---

## Features

### Authentication
- Simple password-protected login (session based)
- Secure logout

### File Explorer
- Directory browsing with breadcrumb navigation
- Grid view and List view
- Live search / filter by filename
- Sort by Name, Size, or Date
- Show / hide hidden files
- Pagination (100 items per page)
- Drag & drop multi-file upload
- Create new file and new folder
- Download files
- Online file viewer + editor
- Image preview
- Rename, Copy, Move, Delete (single + batch)
- Zip and Unzip support
- Batch Zip & Download
- View and change permissions (`chmod`)
- Recursive folder size calculator
- Duplicate file finder (name + size)
- Fullscreen explorer mode

### Root Mode (Sudo)
- Unlock elevated privileges with sudo password
- Browse, view, edit, download and modify protected files/folders
- Auto-locks after 30 minutes of inactivity

### Terminal
- Interactive command execution
- Built-in commands: `help`, `clear`, `date`, `whoami`, `pwd`, `ls`, `sysinfo`, `cat`
- Full shell command support

### System Overview
- Real-time CPU load, Memory usage, Disk usage, Uptime (AJAX)
- Hostname, Kernel version, Client IP, Server IP
- Process count
- PHP version and SAPI information

### Advanced System Information
- Running processes
- Network interfaces
- Open ports
- Running services
- Loaded PHP extensions
- Disabled functions, upload limit, memory limit

### User Interface
- Dark cyberpunk theme with matrix rain background
- Fully responsive design
- Flash success/error messages
- Floating selection bar for batch operations

---

## Requirements

- PHP 7.4 or higher (PHP 8.x recommended)
- `proc_open` and `shell_exec` enabled
- Recommended extensions:
  - `ZipArchive`
  - `posix`
- `sudo` access (only if you want to use Root Mode)

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/SNIPER.git
   cd SNIPER
