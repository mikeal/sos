# SOS -- Secure Object Standard

```
{
  data:
    {encoding: str
     nonce: <nonce> // optional
     contentType: 'application/json' // optional, only relates to buffer encodings
    }
  from:
    data: {encoding: str}
  to: // optional, when supplied contents are signed.
    data: {encoding: str}
  signature:
    {
      data:
        {encoding: str}
      authorities:
        [SOS, SOS, SOS]
    }
}
```

## Encodings

The encoding for JSON takes a standard JSON object. The signature
validation is a Buffer of `JSON.stringify()` body of the object.

All other encodings are binary, the key describes how it was encoded to
string. `hex` and `base64` are the only currently allowed.

Note that signature authorities must be json encoded.

### Authorities

```
[
  {
    data:
      {
        json:
        {
          publicKey:
            {encoding: str}
          /* Additional information about this user */
        }
      }
    from:
      {} // authority
    signature:
      {} // standard signature, includes authorities.
  }
]
```

