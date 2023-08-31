## Building the source

Follow the "Build from source code" section in [this document](https://geth.ethereum.org/docs/getting-started/installing-geth).

## Specific steps for Windows

Follow the "Build from source code"\"Windows" section in [this document](https://geth.ethereum.org/docs/getting-started/installing-geth).
if you see errors like "missing go.sum entry for module ...", run this command
```shell
go mod tidy
```

### Check if geth is successfully built
```shell
where geth
```

### One-time setup
```shell
xcopy [repo-dir]\TCT-Geth-1\TCTchain d:\TCTchain /I
cd d:\TCTchain
d:
geth account new --datadir node1
```
When asked for password, use "a1" as the password, which is stored in pwd.txt.
Copy the created address, e.g, 0x3a12DBb7B3C8aB6e927F869A04Ea9F9596F2ce07. Paste the address into extradata and alloc of PoA-genesis.json.
```shell
geth init --datadir node1 PoA-genesis.json
```

### Run geth with miner
```shell
geth --datadir node1 --http --http.corsdomain https://remix.ethereum.org --networkid 12345 --vmdebug --allow-insecure-unlock --password pwd.txt --unlock "0x3a12DBb7B3C8aB6e927F869A04Ea9F9596F2ce07" --mine --miner.etherbase "0x3a12DBb7B3C8aB6e927F869A04Ea9F9596F2ce07"
```

### Interact with geth
Use browser to visit [online remix](https://remix.ethereum.org/).
Click "Deploy & Run Transactions". In "Environment", choose "Custom - External Http Provider". Accept the default endpoint "http://127.0.0.1:8545".
The account should now have 420 ether.

## License

The go-ethereum library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The go-ethereum binaries (i.e. all code inside of the `cmd` directory) are licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.
