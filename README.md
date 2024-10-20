# opensmtpd-spf

SPF filter for opensmtpd.
Requires python3 spf module

Tested with openbsd 7.5 and 7.6

# Installation
#pkg_add py3-spf 

Get checkspf.py, make it executable and move it to /usr/local/libexec/smtpd/ 

In smtpd.conf, add filter for SPF

"filter checkspf proc-exec checkspf.py"

and add the filter to your listenning interface 

"listen on em0 filter checkspf"

restart smtpd.

# Disclaimer
This filter tries to respect the SPF RFCs, but does not consider DMARC !

!!WARNING!! use this at your own risk: some legitimate mails could be dropped, and some spam could still find it's way in.

This works for me and saved me from many spams, I did not lost any ham with it (yet).

Some spam will be dropped during smtp session, some will make it to Junk folder.

Take a look for 'SPF' strings in logs for spam attempts.

I'm not a python developer.
