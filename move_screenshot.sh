#!/bin/bash
cd ~/Pictures/Screenshots
mv "$(ls | tail -1)" ~/Desktop/CyberS/CyberLabInternship/Inpt-report/images
cd ~/Desktop/CyberS/CyberLabInternship/Inpt-report/images
mv "$(ls | tail -1)" "$(($(ls | tail -2 | head -1 | cut -d "." -f 1) + 1)).png"
echo -e "\n\n" >> ../README.md
echo "![](https://github.com/Farrhouq/Inpt-report/blob/main/images/$(ls | tail -1))" >> ../README.md
