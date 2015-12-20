#!/bin/sh

#
# Makefile for jars.
# (C) 2015 Sebastian Deiss. All rights reserved.
#


APP_NAME="Java-PBKDF2"
PACKAGES="de/hawlandshut/sdeiss/pbkdf2/*.java org.bouncycastle/*/*.java"

echo "Building $APP_NAME.jar\n"


# Create jar
# check if bin/ directory exists, if not create it
if [ ! -d "bin/" ];
then
	mkdir "bin/"
fi
cd src/ && javac $PACKAGES -d ../bin/
cd ../bin/ && jar cvfm ../$APP_NAME.jar ../Manifest.txt ./ ../License.txt
echo "Done"
