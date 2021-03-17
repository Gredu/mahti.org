#!/bin/bash

git push origin master
hugo
pass -c mahti.org/mahti.orgServer
lftp -c "open -u mahti,$(xclip -o) ftp.mahti.org; set ftp:ssl-allow no; set ssl:verify-certificate no; mirror -R public/ ~/public_html/"
rm -r public
