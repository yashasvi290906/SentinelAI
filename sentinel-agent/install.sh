#!/bin/bash
echo "Installing SentinelAI Agent..."
pip3 install -r requirements.txt
cp config.yaml /etc/sentinel-agent/config.yaml 2>/dev/null || mkdir -p ~/.sentinel-agent && cp config.yaml ~/.sentinel-agent/config.yaml
echo "Run: python3 agent.py --test"