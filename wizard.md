---
wizard: 0.2
id: wizard-whoop
name: WHOOP
type: external
category: system
version: 0.2.3
summary: Connect your WHOOP. Health and your other apps get read-only recovery, sleep, strain and workouts.
tags: [health, whoop, fitness]
license: GPL-3.0-only
source: https://github.com/oscarhenrycollins/wizard-whoop
runtime:
  kind: runtipi
  config: runtipi/config.json
  compose: runtipi/docker-compose.yml
api:
  port: 8824
  path: /api
  spec: openapi.json
mcp:
  path: /mcp
  port: 8824
  transport: streamable-http
skill: skill/SKILL.md
view:
  path: /
  port: 8824
  source:
    path: web
    build: python3 app/build_view.py
    dist: web
provides: [health-data, whoop-health-data]
system: true
uses: []
needs: []
health: /healthz
---

# WHOOP

Connects one WHOOP account to your Wizard. The app walks you through setup on its own screen: you need a WHOOP membership (any tier), you create a free app on WHOOP's developer dashboard, paste its Client ID and Client Secret here, then sign in to WHOOP once in your own browser and paste the address it lands on back into the app. The keys and sign-in stay inside this app and are never shown again.

After sign-in the app downloads your full WHOOP history, then checks for new data every 20 minutes (a private box can't receive WHOOP webhooks). It keeps the copy here and offers it, read-only, to other apps on this box through the `health-data` spot (contract `wizard.health-data/1`, see `docs/health-data-contract.md`). The Health app shows it: today, trends and workouts. Your agent gets narrow tools to check the connection and ask for a sync.

Disconnect signs out of WHOOP and deletes the local copy.
