# ShieldNet Browser Extension

Load this directory as an unpacked Manifest V3 extension in Chromium. It scans
only when the toolbar button or context-menu action is used. The default API is
`http://127.0.0.1:8000`; configure its API key from the extension settings.

The manifest intentionally grants host access only to loopback. Managed
deployments using another API origin must add that exact origin to
`host_permissions` through their build or browser policy.

