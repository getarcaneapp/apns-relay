<div align="center">

# apns-relay

Push notification relay for the Arcane mobile app.

<a href="https://github.com/getarcaneapp/apns-relay/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-blue.svg" alt="License"></a>

</div>

Delivers Arcane notifications to iOS devices over APNs and Android devices over FCM
without learning where your Arcane server lives or who its users are. Arcane signs each
notification, the relay verifies it and forwards it to Apple or Google.

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

## Android (FCM)

FCM delivery is off by default. To turn it on, create a service account key in the
Firebase console (Project settings → Service accounts) and set:

| YAML (`fcm:`)          | Environment                | Notes                                          |
| ---------------------- | -------------------------- | ---------------------------------------------- |
| `mode`                 | `FCM_MODE`                 | `disabled` (default), `live`, or `log`         |
| `service_account_file` | `FCM_SERVICE_ACCOUNT_FILE` | Path to the service account JSON key           |
| `service_account`      | `FCM_SERVICE_ACCOUNT_JSON` | The JSON key inline, instead of a file         |
| `project_id`           | `FCM_PROJECT_ID`           | Defaults to the key's `project_id`             |
| `token_url`            | `FCM_TOKEN_URL`            | Tests only; defaults to the key's `token_uri`  |
| `base_url`             | `FCM_BASE_URL`             | Defaults to `https://fcm.googleapis.com`       |

The Android app registers with `POST /v1/installations` using `"platform": "fcm"` and
its FCM registration token as `deviceToken` (no `apnsEnvironment`).

The service account must belong to the same Firebase project as the app's
`google-services.json`. If it doesn't, sends fail with `SENDER_ID_MISMATCH` (visible in
`relay_fcm_responses_total`); installations are kept so fixing the key restores delivery.
Only `UNREGISTERED` and malformed tokens remove an installation.

The relay sends high-priority **data-only** messages whose keys follow the
[expo-notifications payload format](https://docs.expo.dev/versions/latest/sdk/notifications/#android-push-notification-payload-specification),
so the app presents them without a custom `FirebaseMessagingService`, even when it isn't
running. Messages carry no `collapse_key` (FCM would keep only four distinct alerts for an
offline device); repeats replace each other through `tag` instead. The `data` map contains:

| Key                | Value                                                                 |
| ------------------ | --------------------------------------------------------------------- |
| `title`            | Notification title                                                    |
| `message`          | Notification body                                                     |
| `tag`              | Stable per alert, so a repeat replaces the alert already in the tray  |
| `threadIdentifier` | `environmentId:type`, used as the notification group                  |
| `channelId`        | `arcane`; the app must create this notification channel               |
| `body`             | JSON **string** `{"arcane":{…}}`; the same `arcane` object as in APNs |

expo-notifications parses `body` into the notification's `data`, so the app reads
`data.arcane` on both platforms.

## License

apns-relay is released under the BSD 3-Clause License.
