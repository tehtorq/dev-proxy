# dev-proxy

> A puma-dev inspired development server proxy for Node.js applications

Automatically start and stop your development servers on-demand with zero configuration. Perfect for teams managing multiple frontend applications.

## Who Is This For?

- **Frontend developers** working on multiple Node.js/JavaScript applications
- **Full-stack teams** running several microservices locally
- **Anyone tired of** manually starting/stopping dev servers or keeping them all running
- **Former puma-dev users** looking for a Node.js equivalent

## What Does It Support?

### Frameworks & Build Tools
- ✅ Vite (Vue, React, Svelte, SvelteKit, etc.)
- ✅ Next.js
- ✅ Astro
- ✅ Create React App
- ✅ Webpack Dev Server
- ✅ Any Node.js dev server that outputs its URL

### Package Managers
Auto-detects and uses the right one:
- npm
- pnpm
- yarn

### Operating Systems
- macOS ✅
- Linux ✅
- Windows ⚠️ (Basic functionality works, but graceful shutdown requires Ctrl+C handling. Signal handling is Unix-only)

## Features

- **Zero configuration** - No YAML files, just symlinks
- **Auto-start on demand** - Servers start when you access them
- **Auto-shutdown** - Stops after 15 minutes of inactivity
- **Port auto-detection** - Reads port from dev server output
- **Package manager detection** - Automatically uses npm/pnpm/yarn
- **Single port routing** - All apps accessible through one port
- **WebSocket support** - Hot Module Replacement (HMR) works perfectly
- **Connection limiting** - Prevents resource exhaustion on heavy loads
- **Simple CLI** - Easy add/remove/list commands
- **Split-panel TUI** - Visual interface with server status, logs, and control (default!)
- **Process group management** - Clean shutdown with no orphaned processes

## Installation

### macOS

```bash
# Clone and build
git clone <this-repo>
cd dev-proxy
cargo build --release

# Install to system PATH
sudo cp target/release/dev-proxy /usr/local/bin/

# Verify installation
which dev-proxy
# Should output: /usr/local/bin/dev-proxy

# You can now run dev-proxy from any terminal
dev-proxy
```

### Linux

```bash
# Clone and build
git clone <this-repo>
cd dev-proxy
cargo build --release

# Option 1: System-wide install (requires sudo)
sudo cp target/release/dev-proxy /usr/local/bin/

# Option 2: User-only install (no sudo required)
mkdir -p ~/.local/bin
cp target/release/dev-proxy ~/.local/bin/
# Add to PATH: export PATH="$HOME/.local/bin:$PATH" in ~/.bashrc or ~/.zshrc

# Verify
dev-proxy --version
```

**Note:** On Linux, you may need to install build dependencies first:
```bash
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install gcc openssl-devel

# Arch
sudo pacman -S base-devel openssl
```

## Quick Start

### Setup Your Apps

```bash
# Add your projects (creates symlinks automatically)
dev-proxy add admin ~/code/admin-app
dev-proxy add dashboard ~/code/dashboard-app
dev-proxy add api ~/code/api-frontend

# List configured servers
dev-proxy list
```

Output:
```
Configured servers:

  admin → http://admin.test
    /Users/you/code/admin-app

  dashboard → http://dashboard.test
    /Users/you/code/dashboard-app

  api → http://api.test
    /Users/you/code/api-frontend
```

### Configure Caddy

Add one line to your Caddyfile:

```
*.test {
    reverse_proxy localhost:3000
    tls internal
}
```

Or with a custom domain suffix:

```
*.mycompany.test {
    reverse_proxy localhost:3000
    tls internal
}
```

Then run dev-proxy with:
```bash
dev-proxy --domain-suffix mycompany.test
```

### Start dev-proxy

```bash
dev-proxy
```

Output:
```
🔍 Scanning /Users/you/.dev-proxy for dev servers...
   📌 admin.test → /Users/you/code/admin-app
   📌 dashboard.test → /Users/you/code/dashboard-app
   📌 api.test → /Users/you/code/api-frontend
🎯 DevProxy starting with 3 servers on port 3000
📡 Proxy listening on 127.0.0.1:3000
✨ DevProxy ready! Press Ctrl+C to stop.
```

### Browse to Your Apps

Visit `http://admin.test` in your browser:

```
🚀 [admin] Starting dev server (auto-detecting port)...
[admin] > npm run dev
[admin]   VITE v5.4.0  ready in 234 ms
[admin]   ➜  Local:   http://localhost:5173/
🔍 [admin] Detected port: 5173
✅ [admin] Dev server ready on port 5173
🔌 [admin.test] WebSocket upgrade request
🔌 WebSocket tunnel established
```

Your app loads! HMR works! After 15 minutes of inactivity, it automatically stops.

## TUI Mode (Default)

dev-proxy now starts with a split-panel terminal interface by default:

```bash
# Run with TUI (default)
dev-proxy

# Or disable TUI for plain logging
dev-proxy --no-ui
```

**Interface:**
```
┌────────────────────────────────────┬─────────────────────────────────┐
│ Servers                            │ Logs: admin                     │
│ (↑↓=Nav Enter=Open k=Kill r=Res..│ (c=Copy f=Flush A/Z=Scroll...)  │
│                                    │                                 │
│ ◉ All                              │ [admin] > npm run dev           │
│ ● admin.test                       │ [admin] VITE ready in 234ms     │
│ ○ dashboard.test                   │ [admin] ➜ http://localhost:5176 │
│ ● phone.test                       │ 🔍 Detected port: 5176          │
│                                    │ ✅ Dev server ready on port 5176│
└────────────────────────────────────┴─────────────────────────────────┘
```

### Navigation

**Server List (Left Panel):**
- `↑/↓` - Navigate servers
- `Enter` - Open selected server in browser
- `Home/End` - Jump to first/last server

**Server Control:**
- `k` - Kill selected server (stops until manually restarted or browser visit)
- `r` - Restart selected server
- `q` or `Esc` - Quit dev-proxy

**Log Viewing (Right Panel):**
- `A/Z` - Scroll logs up/down (5 lines at a time)
- `T` - Jump to top of logs
- `B` - Jump to bottom of logs
- `c` - Copy all logs to clipboard
- `f` - Flush/clear logs for selected server
- **Mouse wheel** - Scroll logs
- **Shift + drag** - Select text to copy (in most terminals)

### Features

- **Live log streaming** - See logs for selected server in real-time
- **Status indicators** - ● green (running) / ○ gray (stopped)
- **Auto-scroll** - Logs follow new output when scrolled to bottom
- **Scrollbars** - Visual indicator of log position
- **Multi-server view** - Select "All" to see logs from all servers
- **Clean shutdown** - Kills entire process groups (no orphaned processes)

## How It Works

```
┌─────────┐      ┌───────┐      ┌───────────┐      ┌──────────────────┐
│ Browser │─────>│ Caddy │─────>│ dev-proxy │─────>│ Your Dev Servers │
└─────────┘      └───────┘      └───────────┘      └──────────────────┘
                  *.test         Single port         Auto-started
                                 Routes by            on-demand
                                 Host header
```

1. **Symlink scanning** - Scans `~/.dev-proxy/` for symlinks on startup
2. **Domain mapping** - Symlink name becomes `<name>.<suffix>` domain
3. **Request routing** - Reads `Host` header to determine which server to use
4. **On-demand startup** - Starts dev server when first request arrives
5. **Port detection** - Parses dev server output for `http://localhost:XXXX`
6. **Request proxying** - Forwards all requests with proper headers
7. **WebSocket tunneling** - Handles WebSocket upgrades for HMR
8. **Auto-shutdown** - Stops servers after idle timeout (default 15 min)

## Commands

### `dev-proxy add <name> <path>`

Add a new development server.

```bash
dev-proxy add myapp ~/code/myapp
```

- Creates symlink at `~/.dev-proxy/myapp`
- Server becomes accessible at `http://myapp.test`

### `dev-proxy remove <name>`

Remove a development server.

```bash
dev-proxy remove myapp
```

- Deletes the symlink (doesn't touch your actual code)

### `dev-proxy list`

List all configured servers.

```bash
dev-proxy list
```

### `dev-proxy` (default)

Run the proxy server.

```bash
# With defaults
dev-proxy

# With custom options
dev-proxy --port 8080 --domain-suffix dev --dir ~/my-projects
```

## CLI Options

```
-d, --dir <DIR>
    Path to symlink directory [default: ~/.dev-proxy]

-p, --port <PORT>
    Port to listen on [default: 3000]

-s, --domain-suffix <DOMAIN_SUFFIX>
    Domain suffix [default: test]

--no-ui
    Disable TUI mode (use plain logging instead)

-h, --help
    Print help

-V, --version
    Print version
```

## Advanced Usage

### Plain Logging Mode

If you prefer traditional log output without the TUI:

```bash
# Disable TUI
dev-proxy --no-ui

# With custom settings
dev-proxy --no-ui --domain-suffix dev --port 8080
```

Logs will be printed directly to stdout/stderr instead of the split-panel interface.

### Custom Domain Suffix

```bash
# Use .dev instead of .test
dev-proxy --domain-suffix dev

# Now your apps are at:
# - admin.dev
# - dashboard.dev
```

Update your Caddyfile:
```
*.dev {
    reverse_proxy localhost:3000
}
```

### Custom Symlinks Directory

```bash
dev-proxy --dir ~/my-servers

# Add servers to ~/my-servers/ instead of ~/.dev-proxy/
dev-proxy --dir ~/my-servers add myapp ~/code/myapp
```

### Run on System Startup

<details>
<summary>macOS (launchd)</summary>

Create `~/Library/LaunchAgents/com.devproxy.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.devproxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/dev-proxy</string>
        <string>--no-ui</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/devproxy.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/devproxy-error.log</string>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/com.devproxy.plist
```
</details>

<details>
<summary>Linux (systemd)</summary>

Create `~/.config/systemd/user/devproxy.service`:

```ini
[Unit]
Description=DevProxy - On-demand development server proxy

[Service]
ExecStart=/usr/local/bin/dev-proxy --no-ui
Restart=always

[Install]
WantedBy=default.target
```

Enable it:
```bash
systemctl --user enable --now devproxy
```
</details>

## Comparison to Similar Tools

| Feature | puma-dev | dev-proxy | Caddy alone |
|---------|----------|-----------|-------------|
| Config method | Symlinks | Symlinks ✅ | Manual config |
| Auto-start | Yes | Yes ✅ | No |
| Auto-shutdown | Yes | Yes ✅ | No |
| Port detection | Reads .port file | Parses output ✅ | Manual config |
| Package manager | Manual | Auto-detected ✅ | N/A |
| WebSocket support | Yes | Yes ✅ | Yes |
| Language | Go | Rust | Go |
| Primary use case | Ruby/Rails | Node.js/Frontend | General proxy |

## Troubleshooting

### No servers found

```bash
# Check your symlinks directory
ls -la ~/.dev-proxy

# Add a server
dev-proxy add myapp ~/code/myapp
```

### Port not detected

The proxy waits 15 seconds for port detection. If it fails:

```
⚠️  [myapp] Could not detect port, waited 15s
❌ [myapp] Failed to detect port
```

**Solution**: Make sure your dev server outputs the URL with the port:
- ✅ Good: `http://localhost:3000` or `http://localhost:5173/`
- ❌ Bad: `Server running` (no URL)

Most modern dev servers (Vite, Next.js, etc.) output this automatically.

### Server not starting

In the TUI, select the server in the left panel to view its logs in the right panel. You'll see your dev server's output:

```
[admin] > vite
[admin]   VITE v5.0.0  ready in 234 ms
[admin]   ➜  Local:   http://localhost:5173/
```

If you see errors here, they're from your dev server, not dev-proxy.

### Port already in use

If dev-proxy won't start and shows "Address already in use":

```bash
# Check if another instance is running
ps aux | grep dev-proxy

# Kill it if needed
killall dev-proxy

# Or use a different port
dev-proxy --port 8080
```

### Connection issues on first load

This is normal for heavy applications. The browser makes many parallel requests while the app compiles. Just refresh - subsequent loads will be fast.

## How Port Detection Works

dev-proxy parses your dev server's stdout/stderr for patterns like:
- `http://localhost:3000`
- `https://localhost:5173/`
- `http://127.0.0.1:8080`
- `http://myapp.test:4000/`

It automatically detects the first port number it sees and uses that.

## Requirements

- **Rust** - For building from source
- **Caddy** - Or any reverse proxy that can forward to localhost:3000
- **Node.js** - For your dev servers (duh!)

## Why dev-proxy?

If you're juggling multiple frontend apps and tired of:
- Manually starting `npm run dev` in 5 different terminals
- Keeping all dev servers running all the time (memory hog)
- Remembering which app runs on which port
- Configuring each app in your reverse proxy

Then dev-proxy is for you. It brings the puma-dev workflow to the Node.js ecosystem.

## Example Workflow

```bash
# Monday morning - start dev-proxy
dev-proxy
# → Opens TUI with all your configured servers

# Navigate to admin with ↑/↓, press Enter to open in browser
# → dev-proxy auto-starts the server
# → Watch logs in real-time in the TUI

# Switch to dashboard - press ↓ to navigate, Enter to open
# → Starts automatically
# → Both servers now running (green ● indicators)

# Check what's happening - select "All" to see logs from all servers
# Or select individual servers to see filtered logs

# Need to restart a server? Press 'k' to kill, 'r' to restart
# Logs getting cluttered? Press 'f' to flush them

# Lunch break - 15 minutes later
# → Both servers auto-stopped (gray ○ indicators)

# Afternoon - browse to admin again
# → Auto-starts, you see the startup logs in real-time

# End of day - press 'q' in the TUI
# → All dev servers gracefully stopped, process groups cleaned up
```

## Contributing

Issues and PRs welcome! This tool was built to solve a real workflow problem.

## License

MIT

## Credits

Inspired by [puma-dev](https://github.com/puma/puma-dev) - the excellent development server manager for Ruby/Rails applications.
