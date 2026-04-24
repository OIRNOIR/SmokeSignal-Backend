# SmokeSignal Backend

This is the backend for a project I made in May-June 2024. It is an end-to-end encrypted
web-based chat application which uses the quantum-resistant cryptography algorithm
CRYSTALS-Kyber for security.

Please note that the implementation of CRYSTALS-Kyber this project depends on has since
been deprecated in favor of ML-KEM. You may wish to not deploy this project.

It isn't currently actively maintained, and hasn't been actively developed since I originally
wrote it as closed source. If you're reading this, I've released the project as open source as
of October 2025, mostly as an educational proof of concept, but also to showcase my experience.

This backend requires a partner frontend, located [here](https://git.oirnoir.dev/OIRNOIR/SmokeSignal-Frontend).
First replace all instances of `FRONT_HOSTNAME` with your frontend's hostname and
`MONGODB_HOSTNAME` with the hostname of your mongodb server.
These are just in index.ts. Then, make a copy of
`config.json.example` and rename it to `config.json`. There, add your desired port and
a hash of the key used to generate invites to create an accounts. Host this backend
at a separate hostname, referred to at the frontend readme as `API_HOSTNAME`. Finally,
host the frontend and point it at your instance. I typically run this with PM2 via bun.

I apologize for the limited portability of this code. I hastily rewrote it in Typescript
prior to release to attempt to make it a little better, but I don't intend to provide
any future maintenance or documentation for this project. Commit history has been expunged
to avoid exposing personally identifiable information.

To install dependencies:

```bash
bun install
```

If you would like a small demo image, I've attached a (quite badly) censored demo I made at the time.

<img width="7168" height="4416" alt="Demo Image" src="https://github.com/user-attachments/assets/9027471a-ca65-4d40-9394-5464b7681468" />
