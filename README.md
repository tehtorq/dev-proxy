# dev-proxy

Auto-start and stop Node.js dev servers on-demand. Like puma-dev, but for frontend apps.

## Features

- **Zero config** - Just symlinks, no YAML files
- **Auto-start** - Servers start when you visit them
- **Port auto-detection** - Reads from dev server output
- **TUI mode** - Split-panel interface with logs and keyboard controls
- **Text selection** - Navigate logs with arrows, select with Space, auto-copy to clipboard
- **WebSocket support** - HMR works
- **Package manager detection** - Auto-detects npm/pnpm/yarn

**Supported:** Vite, Next.js, Astro, Create React App, Webpack Dev Server, or any Node.js dev server that outputs its URL.

**Platforms:** macOS, Linux (Windows has limited signal handling)

## Installation

```bash
cargo build --release
sudo cp target/release/dev-proxy /usr/local/bin/
```

**Linux dependencies (if needed):**
```bash
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config libssl-dev
```

## Quick Start

```bash
# Add your apps
dev-proxy add admin ~/code/admin-app
dev-proxy add dashboard ~/code/dashboard-app

# Configure Caddy (one-time setup)
echo '*.test {
    reverse_proxy localhost:3000
    tls internal
}' >> /etc/caddy/Caddyfile
sudo systemctl reload caddy

# Start dev-proxy
dev-proxy

# Visit http://admin.test - server auto-starts
```

## TUI Keyboard Controls

**Server List (Left Panel):**
- `↑/↓` - Navigate servers
- `→` - Focus logs panel for text selection
- `Enter` - Open server in browser
- `k` - Kill server
- `r` - Restart server

**Logs Panel (Right Panel - Normal Mode):**
- `→` - Enter text selection mode
- `c` - Copy all logs to clipboard (ANSI codes stripped)
- `f` - Clear logs
- `A/Z` - Scroll 5 lines
- `T/B` - Jump to top/bottom
- Mouse wheel - Scroll

**Logs Panel (Text Selection Mode):**
- `↑/↓` - Navigate lines (cursor highlighted)
- `Space` - Start selection (press again to end and auto-copy to clipboard)
- `←` - Exit selection mode

**Global:**
- `q` or `Esc` - Quit

**Status:** ● green (running) / ○ gray (stopped)

Run without TUI: `dev-proxy --no-ui`

## How It Works

1. Scans `~/.dev-proxy/` for symlinks → creates `<name>.test` domains
2. Browser → Caddy (`*.test`) → dev-proxy (routes by Host header)
3. First request → auto-starts dev server → detects port from output
4. Proxies requests with WebSocket support for HMR

## Commands

```bash
dev-proxy add <name> <path>    # Add server (creates symlink)
dev-proxy remove <name>        # Remove server (deletes symlink)
dev-proxy list                 # List configured servers
dev-proxy                      # Run proxy (with TUI)
dev-proxy --no-ui              # Run without TUI
```

**Options:**
- `--port <PORT>` - Listen port (default: 3000)
- `--domain-suffix <SUFFIX>` - Domain suffix (default: test)
- `--dir <DIR>` - Symlinks directory (default: ~/.dev-proxy)

## Run on Startup (Optional)

**macOS:** Create `~/Library/LaunchAgents/com.devproxy.plist` with the binary path set to `/usr/local/bin/dev-proxy --no-ui`, then `launchctl load ~/Library/LaunchAgents/com.devproxy.plist`

**Linux:** Create systemd user service at `~/.config/systemd/user/devproxy.service`, then `systemctl --user enable --now devproxy`

## Troubleshooting

**Port not detected:** Dev server must output its URL (e.g., `http://localhost:5173`). Modern frameworks do this automatically.

**Port in use:** Check if dev-proxy is already running: `ps aux | grep dev-proxy`

**Server won't start:** Select it in TUI to view error logs in the right panel.

## License

MIT - Inspired by [puma-dev](https://github.com/puma/puma-dev)
