# Tartlet CLI

The `tartlet` command signs you in to a Tartlet server and connects you to your VMs.
It needs Node.js 22.14 or later. Native Windows is untested.

## Quick start

Run the CLI with `npx`. You do not need to install it first:

```sh
npx @tartlet/cli login
```

The examples below use `tartlet`. If you did not install the CLI globally, use
`npx @tartlet/cli` in its place.

During installation, npm or npx may try to compile `ssh2`'s optional native helper.
The CLI also runs without that helper.

### Sign in

```sh
tartlet login
```

`login` opens your browser. After you sign in, you choose a server from your account.
To sign in to a server directly, give its address:

```sh
tartlet login --server https://example.com
```

Other options:

- `--device` shows a code that you enter in a browser on any device.
- `--ca ./root.pem` trusts a private HTTPS root certificate from your administrator.
  The CLI saves a pin of that certificate with the profile.
- `--profile <name>` names the profile, or selects a saved one.

### Open a shell or run a command

```sh
tartlet ssh vm-example
tartlet ssh vm-example -- 'uname -a'
```

Give a VM name or a task label. If a label is the same as a VM name, add `--label`
to match labels only.

### Copy a file

```sh
tartlet cp ./file vm-example:/tmp/file
tartlet cp vm-example:/tmp/file ./file
```

`cp` copies one file in each run.

### Use OpenSSH or VS Code

`tartlet proxy vm-example` sends an SSH connection through standard input and output,
so OpenSSH can use it as a `ProxyCommand`. Install the CLI globally for native SSH
and VS Code, because the npx cache can move. Then let the CLI write the config for you:

```sh
npm install --global @tartlet/cli
tartlet proxy vm-example --config
ssh -F /path/to/ssh_config vm-example
ssh -F /path/to/ssh_config -N -L 8080:127.0.0.1:8080 vm-example
```

The first command prints the path of the config file. The file sets the VM user, your
key, the VM's host key and the `ProxyCommand`. On macOS or Linux, it includes lines
like these:

```
Host vm-example
  User <vm-user>
  StrictHostKeyChecking yes
  IdentityFile "/path/to/key"
  ProxyCommand '/path/to/node' '/path/to/main.js' 'proxy' 'vm-example' '--profile' 'example.com' '--config-dir' '/path/to/config'
```

In VS Code, choose this file as the SSH configuration file. Do not turn off strict
host key checking. Run `--config` again after the VM is recreated or after you choose
a different key.

### Choose an SSH key

On the first connection, the CLI creates a key in its configuration folder. To use
a different key, run one of these:

```sh
tartlet link ./key.pub
tartlet link ./key.pub --identity ./private-key
tartlet link --agent SHA256:fingerprint
tartlet link --generate
tartlet link
```

`tartlet link` with no options asks you to choose. Add keys that have a passphrase to
your SSH agent. `tartlet unlink` forgets the chosen key. Each connection adds the
chosen key to the VM for a short time. `link` and `unlink` change only local settings.

## Troubleshooting

- `Cannot reach the server's network`: if the server is on a tailnet, turn on
  Tailscale. Then check the server address.
- `The server is down or refused the connection`: check that Tartlet is running at
  the address you signed in to.
- Server errors show as `HTTP <status>: <code>`. For sign-in, the codes are:
  - `invalid_token`: your sign-in ended or your access changed. Run `tartlet login`.
  - `invalid_grant`: the CLI cannot renew the saved sign-in. Run `tartlet login`.
  - `access_denied`: sign-in was not approved. Try again, or ask your administrator
    for access.
  - `expired_token`: the device sign-in code expired. Run `tartlet login --device` again.

## Saved files

The CLI keeps profiles, tokens, keys, SSH config files and `known_hosts` in a private
configuration folder:

- macOS: `~/Library/Application Support/tartlet`
- Linux: `$XDG_CONFIG_HOME/tartlet`, or `~/.config/tartlet`
- Windows: `%LOCALAPPDATA%\tartlet`, with access limited to your account

Set `TARTLET_CONFIG_DIR` or pass `--config-dir <path>` to use a different folder. The CLI does not write to your
`.ssh` folder.

SSH and file traffic goes straight to your server over an HTTPS WebSocket. The Tartlet
cloud only signs you in and lists your servers.
