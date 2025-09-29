#!/bin/bash

echo "Setting up environment..."
pip uninstall -y protobuf
pip install protobuf==3.20.3
echo "Setup completed."
