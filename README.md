<div align="center">

# apns-relay

Push notification relay for the Arcane mobile app.

<a href="https://github.com/getarcaneapp/apns-relay/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-blue.svg" alt="License"></a>

</div>

Delivers Arcane notifications to iOS devices over APNs without learning where your
Arcane server lives or who its users are. Arcane signs each notification, the relay
verifies it and forwards it to Apple.

## Documentation

For setup and configuration, visit the **[official documentation site](https://getarcane.app)**.

## Running

```sh
cp relay.example.yaml relay.yaml
./apns-relay -config relay.yaml
```

Or with Docker:

```sh
docker run -p 3554:3554 -v relay-data:/app/data -v ./relay.yaml:/app/config/relay.yaml:ro ghcr.io/getarcaneapp/apns-relay:latest
```

## License

apns-relay is released under the BSD 3-Clause License.
