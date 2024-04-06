# KAMI CLI - KLI
KAMI CLI strives to be equivalent to the KERIpy CLI.

Sample commands are below.

## Usage

### Working with AIDs

### Creating a keystore for a new AID

```shell
kami init --name <name> --salt <salt> --nopasscode --config-dir <config dir> --config-file <config file>
```

### Incepting an AID in the new keystore

```shell 
kami incept -n <name>
```

### Rotating keys for an AID

```shell
kami rotate -n <name> 
```
