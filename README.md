# multiple_custody

This project builds upon Shamir's Secret Sharing Scheme in order to provide a mechanism for arbitrary key-sharing
schemas.

## WARNING: This is a toy project. Don't use it for anything security-critical.

While I believe this project is safe, I'm not a security expert. I don't have the skills to evaluate whether the methods used
here are safe.

## Schemas

A schema is a JSON file, formatted like so:

```json
{
  "any": [
    {
      "at least 2": [
        "a",
        "b",
        "c"
      ]
    },
    {
      "all": [
        "a",
        {
          "at least 5": [
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j"
          ]
        }
      ]
    }
  ]
}
```

The example schema above specifies ten keyholders (`a`, `b`, ..., `j`). The secret can be recovered under either of two
conditions:

* At least *two* members of the group `a`, `b`, `c` present their shares.
* `a` presents their share **and** at least *five* members of `d`, `e`, `f`, `g`, `h`, `i`, `j` present their shares.

Notice that the outermost value is a dictionary, which has a single key for which the value is a list of either strings
or dicts.

### Tags

Tags are used as the key in each dictionary. There are three types of tags currently supported:

#### `any`

This tag is exactly equivalent to the `or` tag. It requires that *at least one* of its arguments is satisfied.

#### `all`

This tag is exactly equivalent to the `and` tag. It requires that *all* of its arguments are satisfied.

#### `at least <n>`

`n` is a positive integer. This tag requires that `n` or more arguments are satisfied.

## Secrets

`multiple_custody` handles secrets of exactly 128 bits (16 bytes). It accepts multiple encodings, which can be specified
with the `-e` flag.

## Examples

Generate a secret:

```shell
openssl rand -base64 16 > secret.key
```

If we assume this example schema:

```json
{
  "at least 2": [
    "rivest",
    "shamir",
    "adleman"
  ]
}
```

We can use the schema to create shares:

```shell
multiple_custody --encoding base64 encode --schema schema.json --secret secret.key
```

The above command will generate files named after the keyholders:

```shell
ls
# Results: "rivest shamir adleman ..."
```

Since our schema requires at least two of the keyholders, trying to obtain the secret with only a single share will
fail:

```shell
multiple_custody --encoding base64 decode adleman
# Results: error
```

However, if we use two shares, we can recover the secret:

```shell
multiple_custody --encoding base64 decode adleman shamir
# Results: <secret printed on stdout in base64>
```