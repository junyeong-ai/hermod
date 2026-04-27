# Deployment artefacts

Sample service unit files for running `hermodd` under the host's
init system.

## macOS (launchd)

```sh
sed "s|/Users/REPLACE_ME|$HOME|g" deploy/launchd.com.hermod.daemon.plist \
  > ~/Library/LaunchAgents/com.hermod.daemon.plist
launchctl load ~/Library/LaunchAgents/com.hermod.daemon.plist
```

Logs at `~/.hermod/log/hermodd.{out,err}.log`.

## Linux (systemd, user unit)

```sh
mkdir -p ~/.config/systemd/user
cp deploy/systemd/hermod.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hermod.service
journalctl --user -u hermod.service -f
```

## Notes

- Replace the binary path (`/usr/local/bin/hermodd`) if you install
  elsewhere — `$HOME/.cargo/bin/hermodd` for `cargo install` users.
- Federation listening is opt-in — leave `daemon.listen_ws` empty in
  `config.toml` if this host is outbound-only.
