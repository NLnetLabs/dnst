`dnst` fuzz testing with cargo-fuzz and libfuzzer

# tl;dr

For example, fuzz test the nsec3-hash subcommand for 10 minutes using 8 concurrent jobs:

```
cargo +nightly fuzz run nsec3-hash -- -jobs=8 -max_total_time=600 -print_final_stats
```

# Further reading

https://rust-fuzz.github.io/book/introduction.html