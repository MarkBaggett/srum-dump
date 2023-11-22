# Release Notes


1-21-2022  Version 2.4 

 - Updated code so that it supports Windows 11 wireless profile names. The registry key was called "Channel Hints" and now its called "Band Channel Hints".  Now the software will accept either of these names.
 - Change color scheme from "TanBlue" to "Kayak" so you can quickly visually identify if someone is running an old verion.

4-13-2023  Version 2.5 - Bloodsport

- Several Template enhancements by Yogesh Khatri
- Updated ESE Database engine to latest version
- Change Color Scheme to Red.. aka Bloodsport
- Tested for Windows 22H2 build 22621.1555 and below

11-23-2023 Version 2.6 - BloodierSport

 - Added retry on database operations. Unsure of the cause but sometime the libesedb engine raises a traceback when retrieving information from the ese table, but pausing for a second and trying the same query again fixes the issue. Now I retry 5 time with a 0.1 second pause before allowing the error to be raised.  (Einstien was wrong. Trying the same thing over and over sometime yields different results.Then again, I can't rule out insanity.)
 - Keeping Red color scheme. People seem to like it.
 - Tested on Windows 11 22H2 build 19045.3693,22621.2715 and Windows 10.0 Build 10240
 - Built with Python 3.12 and pyinstaller 6.2.0


