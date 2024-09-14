#!/bin/bash
# for automatic pushing of images
git add .
git commit -m "add image $1"
git push
