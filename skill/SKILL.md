---
name: wizard-whoop
description: Use when the owner asks about his WHOOP connection, WHOOP setup or sync. Health questions go to Health.
version: 0.2.3
author: Humanity Labs
license: GPL-3.0-only
metadata:
  hermes:
    tags: [whoop, health-data, connector]
    related_skills: [wizard-health]
---
# WHOOP (connector)

The box's WHOOP connection (`health-data` spot, contract `wizard.health-data/1`). It holds the WHOOP sign-in and a synced copy; the **Health** app (`/wizard-health/`) shows the data and answers health questions. Tools: `mcp__wizard__wizard_whoop__<tool>`.

- Questions about recovery, sleep, HRV, strain, workouts or trends: use the Health app's tools (`health_daily_summary`, `health_days`, `health_trends`, `health_sleep`, `health_workouts`), not these.
- "Is my WHOOP connected / when did it last sync": `health_data_status`. `connected`, `syncing` or `rate_limited` = data is flowing; `not_configured` or `needs_login` = the owner must finish or redo setup.
- Setup, reconnecting or replacing keys: send the owner the app link `[WHOOP](/wizard-whoop/)` and say its screen walks him through it (five steps: membership, WHOOP developer dashboard, create an app with the copy buttons, paste Client ID and Secret, Connect). Never walk him through the WHOOP dashboard in chat, and never ask for or accept a Client ID, Client Secret, password, sign-in code or the localhost callback address in chat; those go only into the app's own screen.
- `health_data_sync` asks for fresh WHOOP data now (the app also syncs every 20 minutes); it returns at once.
- `health_data_days` is the raw contract read (normalized days, paged, `changed_since` cursor). Use it only to check what the connector holds, e.g. when Health looks wrong.
- Scripts on the box can read the same contract at `http://127.0.0.1:8824/api/status` and `/api/days`.
