# FOSSTAK CLIENT

## Build & Run

Install [Rust](https://www.rust-lang.org/) and [Android Studio](https://developer.android.com/studio).

- Go to Android Studio -> SDK Manager -> SDK Tools and install the NDK and the SDK Command-line Tools.

- Install ```cargo-apk```:

    ```sh
    cargo install cargo-apk
    ```

- Install aarch64-linux-android, armv7-linux-androideabi and x86_64-linux-android:
    ```sh
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
    ```

You can run in debug with:
```sh
cargo apk run
```

and in release with: (Currently not working because of no)
```sh
cargo apk run --release
```