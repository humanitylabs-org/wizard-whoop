# WHOOP (Wizard connector)

A Wizard OS connector app for one WHOOP account. It holds the WHOOP sign-in, keeps a private synced copy of cycles (strain), recovery, sleep and workouts, and offers that copy read-only to other apps on the same box through the `health-data` spot, contract [`wizard.health-data/1`](docs/health-data-contract.md). The [Health](https://github.com/oscarhenrycollins/wizard-health) app is the screen for the data; this app is only the connection, the same split as Money over SimpleFIN/Monarch.

## Setup (all on the app's own screen)

1. Active WHOOP membership (any tier); the developer API is free.
2. Sign in at https://developer-dashboard.whoop.com and create a Team.
3. Create App with the values the screen shows (name, Redirect URL, six read scopes; webhooks blank). Each has a Copy button.
4. Paste Client ID and Client Secret (stored server-side, never echoed). The app tests them by exchanging a made-up code (`invalid_grant` = keys valid, `invalid_client` = wrong).
5. Connect with WHOOP: the consent page opens in a new tab of the owner's own browser. After Grant, the browser lands on `http://localhost:3000/callback?code=...` (which doesn't load); the owner pastes that address back and the app finishes the sign-in. The full history downloads automatically, then the app syncs every 20 minutes with a 4-day overlap.

The Redirect URL defaults to `http://localhost:3000/callback` because it works from any browser. Over https the screen also offers the box's own address (`https://<box>/wizard-whoop/callback`), where the app finishes the sign-in by itself.

## Interfaces

- Screen: `/wizard-whoop/` (status, connected account, Sync now, Disconnect, guided setup).
- Contract (box-only: refused when it arrives through the private-access proxy): `GET /api/status`, `GET /api/days?from&to&limit&page&changed_since`. See `docs/health-data-contract.md`.
- Setup API used by the screen: `GET /api/setup`, `POST /api/keys`, `/api/keys/test`, `/api/keys/forget`, `/api/oauth/start`, `/api/oauth/finish`, `/api/sync`, `/api/disconnect`; `GET /callback` for the https Redirect URL.
- MCP (`POST /mcp`, box-only): `health_data_status`, `health_data_sync`, `health_data_days`.

## Development

`python3 -m unittest discover -s tests` runs the tests against a fake WHOOP. `python3 tools/package.py` refreshes the inline Runtipi payload; `python3 tools/package.py --check` verifies it.
