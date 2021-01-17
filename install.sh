#!/bin/bash
BASEDIR=$(dirname $0)
set -e

#CHROMEVERSION="v1.0.0-45"
#DRIVERVERSION="2.40"

CHROMEVERSION="v1.0.0-50"
DRIVERVERSION="2.41"

CHROMEFILE=https://github.com/adieuadieu/serverless-chrome/releases/download/${CHROMEVERSION}/stable-headless-chromium-amazonlinux-2017-03.zip
CHROMEDRIVER=https://chromedriver.storage.googleapis.com/${DRIVERVERSION}/chromedriver_linux64.zip

curl -SL $CHROMEFILE > headless-chromium.zip
unzip headless-chromium.zip 
rm headless-chromium.zip

curl -SL $CHROMEDRIVER > chromedriver.zip
unzip chromedriver.zip 
rm -rf chromedriver.zip

mkdir -p selenium-layer/driver/
mv chromedriver headless-chromium selenium-layer/driver/

cd selenium-layer/
pip3 install -t selenium/python/lib/python3.7/site-packages selenium
pip3 install -t oathtool/python/lib/python3.7/site-packages oathtool
pip3 install -t slackclient/python/lib/python3.7/site-packages slackclient

npm install

cd $BASEDIR/lambda/
npm install
cd $BASEDIR/