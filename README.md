# bitvault

Create a vault for your coins using the experimental BIP345.

## Usage

### Create Vault
Creates a new vault address
```
>bitvault create-vault
New Address: bcrt1p72rulxg5ylmynej0wyp3hmurzqn0jejh7kj2fu67zh40qcj98ahqw8sn29
```

### List Vaults (in development)
List all vault addresses
```
>bitvault list-vaults
```

### Unvault (in development)
Create and send an Unvault spend transaction from the specified vault
```
>bitvault unvault <amount-in-sats> <vault-address>
```

### Unvault (in development)
Create and send a Recovery spend transaction from the specified vault
```
>bitvault recover <amount-in-sats> <vault-address>
```
