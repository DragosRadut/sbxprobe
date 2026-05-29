#!/bin/bash
su - cuckoo -c "source ~/cuckoo-env/bin/activate && cuckoo web runserver 127.0.0.1:8000" &
sleep 2
su - cuckoo -c "source ~/cuckoo-env/bin/activate && cuckoo -d"
