# Tartlet CLI

Sign in and connect to your Tartlet VMs. Requires Node.js 22.14 or later.

```sh
npx @tartlet/cli@0.2.0 login
npx @tartlet/cli@0.2.0 ssh vm-example
npx @tartlet/cli@0.2.0 ssh vm-example -- 'uname -a'
npx @tartlet/cli@0.2.0 cp ./file vm-example:/tmp/file
npx @tartlet/cli@0.2.0 cp vm-example:/tmp/file ./file
```

Use a VM name or task label. Add `--label` if the label also matches a VM name.

To sign in without cloud discovery, run `tartlet login --server https://example.com`.
Add `--device` to sign in with a code. For a local HTTPS CA, add `--ca ./root.pem`
with the root certificate from your administrator. The CLI saves its SHA-256
SPKI pin. Saved server addresses and trust settings stay fixed across cloud
metadata changes. Use `--profile <name>` to choose or name a profile.

## Choose an SSH key

The CLI creates a key in its private configuration folder on your first connection.
To choose another key, run one of these commands:

```sh
tartlet link ./key.pub
tartlet link --agent SHA256:fingerprint
tartlet unlink
tartlet link --generate
```

For a file whose private key has a different name, add `--identity ./private-key`.
Load encrypted keys into your SSH agent. Run `tartlet link` without flags to pick a
key in the terminal. `link` and `unlink` change local settings. Each connection
authorizes the selected public key briefly on the VM.

## Use native SSH or VS Code

Generate a private SSH config and use the path it prints:

```sh
tartlet proxy vm-example --config
ssh -F /path/to/ssh_config vm-example
ssh -F /path/to/ssh_config -N -L 8080:127.0.0.1:8080 vm-example
```

Choose that config as the SSH configuration file in VS Code. It sets the VM user,
identity, pinned host key, and `ProxyCommand`. Keep strict host-key checking enabled.
Regenerate it after a VM is recreated or you change the selected key. `proxy`
without `--config` carries the SSH stream over standard input and output.

## Saved files

Profiles, tokens, keys, SSH configs, and `known_hosts` live under your account's
private configuration folder. The default is the application support folder on
macOS, the XDG config folder on Linux, or Local AppData on Windows.
`TARTLET_CONFIG_DIR` overrides it. Files use UTF-8 without a BOM. Windows folders
get an ACL for the current account. The CLI does not write to your `.ssh` folder.

SSH and file traffic goes directly to your server through an HTTPS WebSocket.
The cloud provides sign-in and a server list. If your server is on a tailnet,
turn on Tailscale before connecting.
