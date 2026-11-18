# Bypass403

Burp Suite Montoya extension for authorized 403-bypass testing.

## Build

```bash
./gradlew shadowJar
```

Java 17 is required. Load `build/libs/Bypass403.jar` in Burp: **Extensions → Installed → Add**.

## Safety

Only URLs in Burp scope are tested. OPTIONS and TRACE methods remain disabled unless **Enable OPTIONS/TRACE** is selected. Payload count, concurrency, delay, and requests/second are configurable.
