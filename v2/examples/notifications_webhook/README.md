# notifications_webhook

Demonstrates Velocity v2's webhook notification plugin end to end: starts
a real local HTTP server as the webhook receiver, registers a
`NotificationRule` for the `kv.put` topic, does a real `kv.Put`, and
proves an actual POST arrived at the receiver (via a channel, not a blind
sleep). Also proves the rule is topic-scoped by removing it and confirming
a subsequent write produces no delivery.

## Run

```sh
go run ./examples/notifications_webhook
```

## Expected output

Shows the receiver's URL, the rule being added and listed, a `Put` call,
the received webhook payload (JSON: topic/source/key/size), the rule
removal, and confirmation that no further delivery occurs afterward.
