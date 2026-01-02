# RDS-Deploy

Internal deployment tool for BusinessVision Remote Desktop access.

## Overview

This project provides a simple way for end users at remote branch locations to set up RDS shortcuts for accessing BusinessVision.

## Components

| File | Purpose |
|------|---------|
| `index.html` | Landing page hosted via GitHub Pages |
| `Install-BV-Remote.bat` | Creates RDS shortcuts on user's desktop |
| `Uninstall-BV-Remote.bat` | Removes RDS shortcuts from user's desktop |

## End User URL

https://chirri88.github.io/rds-deploy/

## How It Works

1. User visits the landing page
2. Clicks "Download Setup Tool"
3. Runs the downloaded `.bat` file
4. Enters the setup password when prompted
5. Two shortcuts are created on their desktop:
   - **BV Remote** - Primary RDS server
   - **BV Remote 2** - Secondary RDS server

## Making Updates

1. Edit files in VS Code
2. Save changes
3. Source Control → Stage → Commit → Sync
4. Changes are live immediately

## Notes

- Password protection prevents unauthorized use
- Uninstall tool available for cleanup if needed
- Compatible with Windows 10 and Windows 11 clients
- Server hostnames defined in the `.bat` files

---

*Internal IT Tool - CHIRRI*
