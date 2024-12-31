#!/bin/bash

echo "----------------------------------------"
echo "MultiScanV1 Installation Starting..."
echo "----------------------------------------"

# Install required dependencies
echo "Installing required Python libraries..."
pip install -r requirements.txt --break-system-packages

if [ $? -eq 0 ]; then
    echo "----------------------------------------"
    echo "Installation Completed!"
    echo "You can run the program using the following command:"
    echo "python scanner.py"
    echo "----------------------------------------"
else
    echo "Error: An issue occurred while installing dependencies."
    echo "Please check your pip installation and internet connection."
fi
