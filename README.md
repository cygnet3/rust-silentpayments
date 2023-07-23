# Silent Payments

This repo is a rust implementation of BIP352: Silent Payments.
This BIP is still under development, and this repo is by no means ready for real use yet.
At this point, the repo is no more than a rust rewrite of the `reference.py` python reference implementation.

The `tests/resources` folder contains a copy of the test vectors as of July 23rd 2023.
However, for ease of reading the data, some slight changes have been made to the formatting:

- Empty labels are given as an empty map `{}` rather than an empty list `[]`
- The label integer `m` is given in 32-byte big-endian hex format

You can test the code using the test vectors by running `cargo test` 
