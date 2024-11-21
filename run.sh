#!/bin/bash

echo "Checking Python libraries..."

missing_lib=0

# Check if aiohttp is installed
python3 -m pip show aiohttp > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Missing library aiohttp. Installing..."
    python3 -m pip install aiohttp
    missing_lib=$((missing_lib + 1))
fi

# Check if cryptography is installed
python3 -m pip show cryptography > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Missing library cryptography. Installing..."
    python3 -m pip install cryptography
    missing_lib=$((missing_lib + 1))
fi

# Check if colorama is installed
python3 -m pip show colorama > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Missing library colorama. Installing..."
    python3 -m pip install colorama
    missing_lib=$((missing_lib + 1))
fi

if [ $missing_lib -eq 0 ]; then
    echo "All required libraries are already installed."
else
    echo "Finished installing missing libraries."
fi

# Check and create the 'keyboxs' directory if it doesn't exist
if [ ! -d "keyboxs" ]; then
    mkdir keyboxs
    echo "Created new folder..."
fi

# Run the Python script
echo "Running check..."
python3 main.py -b keyboxs/

# Pause the script (optional, not needed in bash)
read -p "Press any key to continue..."