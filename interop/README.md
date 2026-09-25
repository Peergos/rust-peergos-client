# Java interop

Checks the Rust client against a live server and the Java client, in both directions. The two halves exchange paths, hashes and link strings through a shared directory.

Needs a server on `localhost:7777` and a `Peergos.jar`.

```sh
J=/path/to/Peergos.jar; S=/tmp/interop
javac -cp $J -d out interop/Interop.java
rust() { cargo run -q -p peergos-fs --example interop -- "$1" $S; }
java() { command java -cp out:$J Interop "$1" $S; }

rust rust-setup
java check-rust
java java-setup
java befriend
rust rust-share
java java-share
rust check-java
java check-rust-wrote
rust rust-mfa
java mfa-login
```
