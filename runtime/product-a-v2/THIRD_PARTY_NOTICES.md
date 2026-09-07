# Product A runtime notices

The public runtime recipe installs OpenAI Codex CLI 0.153.4 for Linux x64 from
the checksum-pinned npm artifact. Codex is licensed under Apache-2.0; see
`LICENSE.codex` and <https://github.com/openai/codex>.

The base is the digest-pinned official Python 3.11.5 image. Debian Bookworm
supplies Git, tinyproxy, and their runtime dependencies from a dated snapshot.
Their package copyright files remain in each image under `/usr/share/doc`.

The three dependency profiles use only the hash-locked wheels already bundled
with the 18 task fixtures. Package metadata and license files remain in their
unpacked `.dist-info` directories under `/sealed-deps`.

Credentials are neither build inputs nor image layers. A user's local Codex
credential is copied only into a temporary runtime mount during isolated
readiness and approved execution, never into a task or evidence.
