#!/bin/bash

# Check if Python 3 is installed
if ! command -v python3 &>/dev/null; then
  echo "Python 3 is not installed. Please install Python 3 and try again."
  exit 1
fi

# Check if pip is installed
if ! command -v pip3 &>/dev/null; then
  echo "pip3 is not installed. Attempting to install pip..."
  python3 -m ensurepip --upgrade
fi

# Install dependencies from requirements.txt
if [ -f "requirements.txt" ]; then
  echo "Installing dependencies from requirements.txt..."
  pip3 install -r requirements.txt
else
  echo "requirements.txt not found. Installing from GitHub source..."
  pip3 install -r https://raw.githubusercontent.com/xiddess/pw-Checker/main/requirements.txt
fi

# Run the main script
echo "Launching pw-Checker..."
python3 main.py
