# reflect.ssh
SSH tunnel redirector that uses usernames as keys for shared connections

## Usage

The server listens on port 2222 and routes connections based on username and port. Multiple reverse tunnels can exist per username on different ports.

### Example: Connecting two machines through the redirector

**Machine A (has a service on port 8080):**
```bash
# Create reverse tunnel - server will listen on port 1234
ssh -R 1234:localhost:8080 alice@redirector-host -p 2222
```

**Machine B (wants to access Machine A's service):**
```bash
# Create forward tunnel - connects to reverse tunnel for username "alice" port 1234
ssh -L 9090:localhost:1234 alice@redirector-host -p 2222
```

**Now Machine B can access Machine A's service:**
```bash
curl http://localhost:9090
```

### How it works

- **Reverse tunnels** (`-R`): Register a listener on the server for a username+port combination. Only one reverse tunnel per username+port is allowed.
- **Forward tunnels** (`-L`): Connect to an existing reverse tunnel by matching username and destination port (destination IP is ignored).
- **Username as key**: All tunnels with the same username share the same connection domain. Different ports within the same username are separate tunnels.

### Notes

- No password authentication required - any username is accepted
- Host key is saved to `host_key` file for persistence
- Multiple connections can exist simultaneously within a username domain on different ports
