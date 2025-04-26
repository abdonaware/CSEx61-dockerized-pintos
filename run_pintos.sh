#!/bin/bash

cd ~ && sudo docker run -it -v "$(pwd)/CSEx61-dockerized-pintos:/root/pintos" a85bf0a348d6 bash -c "
  cd /root/pintos
  git config --global --add safe.directory /root/pintos
  chmod -R 777 .
  git config core.filemode false
  cd ./src/utils
  make clean
  make
  cd /root/pintos/src/threads
  make clean
  make
  bash
"

