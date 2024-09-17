#!/bin/bash
# script for conveniently moving my screenshots from the default directory into /images
images=/home/farouq/Desktop/CyberS/CyberLabInternship/Internal-Network-Pentetrating-Testing/Inpt-report/images
cd ~/Pictures/Screenshots
mv "$(ls | tail -1)" $images
cd $images
mv "$(ls | sort -n | head -1)" "$(($(ls | sort -n | tail -1 | cut -d "." -f 1) + 1)).png"
echo -e "" >> ../README.md
echo "![](https://github.com/Farrhouq/Inpt-report/blob/main/images/$(ls | sort -n | tail -1))" >> ../README.md
