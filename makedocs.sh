#!/bin/sh

#
# Makefile for javadoc documentation.
# (C) 2015 Sebastian Deiss. All rights reserved.
#


APP_NAME="Java-PBKDF2"
PACKAGES="sdeiss.crypto.pkcs5 org.bouncycastle.crypto org.bouncycastle.crypto.digests org.bouncycastle.crypto.macs org.bouncycastle.crypto.params org.bouncycastle.util"

echo "Creating javadoc for $APP_NAME\n"

if [ ! -d "docs/" ];
then
    mkdir "docs"
fi
cd docs/ && javadoc -author -version -private -sourcepath ../src/ -subpackages $PACKAGES
