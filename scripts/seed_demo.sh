#!/bin/bash

# Seed Demo Script - Copy insecure IaC to working directory

set -e

echo "Seeding demo IaC files..."
echo "========================="

# Create demo-working directory if it doesn't exist
mkdir -p demo-working

# Copy sample terraform file
if [ -f "samples/iac/insecure/main.tf" ]; then
    cp samples/iac/insecure/main.tf demo-working/
    echo "✓ Copied samples/iac/insecure/main.tf to demo-working/"
else
    echo "Error: Sample IaC file not found at samples/iac/insecure/main.tf"
    exit 1
fi

echo ""
echo "Demo files seeded. You can now:"
echo "1. cd demo-working"
echo "2. git add main.tf && git commit -m 'Add insecure IaC for demo'"
echo "3. git push origin main"
echo "4. Then trigger the webhook to see the demo in action!"
