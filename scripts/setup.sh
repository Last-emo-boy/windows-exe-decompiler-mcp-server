#!/bin/bash
# Setup script for development environment

echo "Setting up Rikune..."

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

# Setup Python virtual environment
echo "Setting up Python virtual environment..."
cd workers
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "Setup complete!"
