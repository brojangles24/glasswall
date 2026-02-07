GlassWall Firewall

A GUI for UFW (Uncomplicated Firewall) on Linux, styled after Portmaster/Windows Firewall.

Requirements

Linux: This app wraps ufw and ss.

sudo pacman -S ufw iproute2

Privileges: The compiled binary must be run with sudo to modify firewall rules.

Setup

Install deps: npm install

Run dev: sudo npm run tauri dev

Build: npm run tauri build
