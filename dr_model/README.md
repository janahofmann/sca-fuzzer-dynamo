# Installation

* install DynamoRIO somewhere in your system

```bash
cd dynamorio_installation_directory

sudo apt-get install cmake g++ g++-multilib doxygen git zlib1g-dev libunwind-dev libsnappy-dev liblz4-dev
wget https://github.com/DynamoRIO/dynamorio/releases/download/release_9.0.1/DynamoRIO-Linux-9.0.1.tar.gz
tar xf DynamoRIO-Linux-9.0.1.tar.gz
rm DynamoRIO-Linux-9.0.1.tar.gz
cd DynamoRIO-Linux-9.0.1

cat <<EOF > ~/.local/bin/drrun
#!/usr/bin/env bash

~/bin/DynamoRIO-Linux-9.0.1/bin64/drrun \$@
EOF

```

* build dr_model

from the `sca-fuzzer/dr_model` directory:

```bash
mkdir -p build
mkdir -p ~/.local/dr_model
cmake -DDynamoRIO_DIR=$HOME/bin/DynamoRIO-Linux-9.0.1/cmake --config Debug ..
make
cp libdr_model.so ~/.local/dr_model
```

* (if used as a part of revizor) build adapter

from the `sca-fuzzer/dr_model` directory:

```bash
make
cp adapter ~/.local/dr_model
```

# Usage
