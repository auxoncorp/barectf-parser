# barectf-parser &emsp; ![ci] [![crates.io]](https://crates.io/crates/barectf-parser) [![docs.rs]](https://docs.rs/barectf-parser)

A Rust library to parse [barectf]-generated [CTF] trace data.

Rather than attempt to parse the standard [CTF] metadata description file, this library
takes advantage of the simplifying constraints imposed by [barectf], using its
configuration yaml to produce a [CTF] byte-stream parser.

See the [examples](examples/) for getting started.

This library supports [barectf] 3.1.

```bash
cargo run --example events_async -- test_resources/fixtures/full/effective_config.yaml test_resources/fixtures/full/trace/stream
```

## Configuration

The library uses the effective configuration file generated from
the [`show-effective-configuration` command](https://barectf.org/docs/barectf/3.1/cli/usage.html#show-effective-configuration-command).

See the integration test [source](test_resources/src) and [fixtures](test_resources/fixtures) for example invocations.

## Limitations

Most of these will be resolved in future versions.

* The special `auto` variant of the `trace.type.uuid` is not supported
  - You can omit `uuid` altogether or provide one in string form
* The `trace.type.$features.uuid-field-type` field only supports `true` or `false`
  - Doesn't support explicit static array field type; assumes 16 byte static array
* Enumeration field types are always treated as `i64`, regardless of the actual field type
* `minimum-alignment` in structure field types are not supported
* Clock offsets and timestamp rollover tracking is to be done by the caller
  - Types are provided to make it easier
* Static and dynamic array field types don't support nested arrays
* Bit-packed field types are not supported
* `trace.type.$features` and `trace.type.data-stream-types.*.$features` need to be explicitly set (either `false` or some field type)

## LICENSE

See [LICENSE](./LICENSE) for more details.

Copyright 2025 [Auxon Corporation](https://auxon.io)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[ci]: https://github.com/auxoncorp/barectf-parser/workflows/CI/badge.svg
[crates.io]: https://img.shields.io/crates/v/barectf-parser.svg
[docs.rs]: https://docs.rs/barectf-parser/badge.svg
[barectf]: https://barectf.org/docs/
[CTF]: https://diamon.org/ctf/v1.8.3/
