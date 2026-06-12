#!/bin/bash
sudo -i -u cuckoo bash -lc 'source ~/cuckoo-env/bin/activate && cuckoo web runserver 127.0.0.1:8000' &
sleep 2
sudo -i -u cuckoo bash -lc 'source ~/cuckoo-env/bin/activate && cuckoo -d'