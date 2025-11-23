# netwrap

**netwrap** - run a program in an isolated network namespace

## SYNOPSIS

```
netwrap [OPTIONS] PROGRAM [ARGS...]
netwrap SCRIPT_FILE
```

## DESCRIPTION

**netwrap** is a lightweight tool to run a program in an isolated Linux network namespace. It creates a new namespace, sets up a virtual ethernet pair, assigns a random private IP (in the 10.200.x.0/24 range), and executes the specified command inside it.

It supports TCP and UDP port forwarding from the host to the isolated container, allowing services to be exposed selectively.

## OPTIONS

**-h, --help**
Display help message and exit.

**-n, --network=NAME**
Join an existing named network namespace or create one with the specified name. If the namespace exists, the program will join it and share its network stack (IP address, localhost). If it does not exist, it will be created.

**-HOST_PORT:CLIENT_PORT[/PROTOCOL]**
Map a network port from the host to the client program.
For example, **-8080:80** forwards TCP traffic from host port 8080 to container port 80.
To specify UDP, append **/udp** (e.g., **-53:53/udp**).
The default protocol is TCP.
Multiple mappings can be specified.

**--**
Stop parsing **netwrap** options. All subsequent arguments are treated as the program command and its arguments.

## SCRIPT MODE

**netwrap** can be used as a shebang interpreter for script files. In this mode, the file is parsed line-by-line.

- Lines are treated as netwrap arguments, optionally with their dash (**-** or **--**).
- Lines starting with **#** are comments.
- The final line or sequence of escaped lines is the command to execute.

Example **myserver.nw**:

```bash
#!/usr/bin/env netwrap
n = my-service
8080:80
python3 \
  -m \
  http.server \
  80
```

## PERMISSIONS

**netwrap** can detect if it actually needs elevation.
If the user does not have the ability to create networks, **netwrap** will prompt for elevation with **sudo**.

To allow **netwrap** to run as a non-root user, add this line to the **/etc/sudoers** file:

```
$USER ALL = NOPASSWD: SETENV: /path/to/netwrap
```

Note: file capabilities (**setcap(8)**) are insufficient because **netwrap** executes the **ip** command, which does not inherit file capabilities.

## EXAMPLES

Run a Python HTTP server isolated, mapping port 8080 to 80:
`netwrap -8080:80 -- python3 -m http.server 80`

Run a shell inside a new isolated network (no internet access):
`netwrap sh`

Join a shared network named 'backend':
`netwrap -n backend ./my-worker`

## REQUIREMENTS

**netwrap** requires **ip** (iproute2) installed. It attempts to gain privileges via **sudo** if run as a non-root user.
