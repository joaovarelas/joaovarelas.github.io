---
title: Real World CTF 2023 - Ferris Proxy - Reverse Engineering
author: vrls
date: 2023-01-12
#categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [realworld, ctf, ferrisproxy, reverse, engineering, pcap, network analysis, cryptography, key, exchange]
image: /assets/img/posts/2023/01/ca187954bd4476ae0dd959125aec489df2875892fd1278142265b4a793631599.png #og:image
permalink: /posts/2023/01/real-world-ctf-2023-ferris-proxy-reverse-engineering/
#image:
#  src: /assets/img/posts/YYYY/MM/MD5SUMHASH.png
#  width: 350   # in pixels
#  height: 350   # in pixels
---


<!-- ![image](/assets/img/posts/2023/01/ca187954bd4476ae0dd959125aec489df2875892fd1278142265b4a793631599.png) -->


## Introduction

During RealWorldCTF 2022 there was a RE challenge named "Ferris Proxy". The challenge includes 2 executables (`client` and `server`) and a TCP packet capture file (`pcap`) that contains data of communication between the client and server.

Our team ([xSTF](https://xstf.pt)) did not solve the challenge on time but I decided to make a writeup anyway because the challenge was fun and mixed multiple categories besides reverse engineering such as network analysis and also cryptography.

In resume the challenge requires to reverse engineer client & server, understand the protocol and find a way to decrypt the traffic. These type of tools are commonly used by people from countries with heavy internet censorship and monitoring (such as China) however they may introduce flaws that could expose citizens traffic or browsing history when being used with, e.g. standard configurations, default keys, flawed cryptography etc.


## Analyzing the binary

A quick `file` command indicates the files are Linux executables `ELF` 64-bit.

```shell
$ file client server FLAG.pcapng 
client:      ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
    interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
    BuildID[sha1]=fd0a5208bedd3a88e6e85a68a85eefc300da0cd5, with debug_info, not stripped

server:      ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
    interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
    BuildID[sha1]=0db24ed5919dd9d442073779b3a28dcbd03ce884, with debug_info, not stripped

FLAG.pcapng: pcapng capture file - version 1.0
```

Fortunately the ELFs were not stripped and the debug info is included to assist while reversing the binaries.


By having a look at `strings` we read some references to the [tokio-rs](https://tokio.rs/tokio/tutorial) library/platform used for the Rust 🦀 programming language. 


```shell
$ strings client
(...)
read_unaligned<[core::mem::maybe_uninit::MaybeUninit<u8>; 16]>
read<core::mem::maybe_uninit::MaybeUninit<(u32, tokio::io::util::mem::DuplexStream)>>
into_inner<core::mem::maybe_uninit::MaybeUninit<bytes::bytes_mut::BytesMut>>
util
process_transfer
runtime
drop_in_place<tokio::runtime::task::harness::poll_future::{closure#0}::Guard<core::pin::Pin<alloc::boxed::Box<lib::protocol::mux::{impl#3}::process_transfer::{async_fn_env#0}<tokio::io::util::mem::DuplexStream>, alloc::alloc::Global>>>>
drop_in_place<core::result::Result<core::result::Result<(), std::io::error::Error>, tokio::runtime::task::error::JoinError>>
drop<core::result::Result<(), std::io::error::Error>>
AddrNotAvailable
drop_in_place<core::result::Result<(), tokio::sync::mpsc::error::SendError<(u32, tokio::io::util::mem::DuplexStream)>>>
(...)
```


## Network communication


On the `flag.pcap` file we notice the 3-way handshake, both source & destination ports and also the TCP data (unreadable).

Since the first SYN is sent from a seemingly random high port we'll assume the the client started the connection and the server is listening on port `8888`.


![image](/assets/img/posts/2023/01/017d7158dcf24c9e5c35e7b1404299e224163a3953b5ca393b86302be6508712.png)


To understand what the `client` and `server` are supposed to do we execute both on *virtual machines* and observe their behavior by analyzing dynamically.
We start by running the client:

```shell
$ ./client 
Error: Os { code: 111, kind: ConnectionRefused, message: "Connection refused" }
```

This error means the client tried to connect to server but since it is not running, it couldn't connect and exited so we must start the `server` in first place.
In fact the `ss` utility confirms that `server` is indeed listening on `8888` for TCP connections.


```shell
$ ss -tlp
State  Recv-Q Send-Q Local Address:Port   Peer Address:PortProcess                                  
(...)       
LISTEN 0      1024         0.0.0.0:8888        0.0.0.0:*    users:(("server",pid=1665474,fd=9))    
```


After playing with the programs a bit we realize the `client` also starts listening on port `12345`. 
The output from `ss` is the following:


```shell
$ ss -tlp
State  Recv-Q Send-Q Local Address:Port   Peer Address:PortProcess                                  
(...)                        
LISTEN 0      1024         0.0.0.0:8888        0.0.0.0:*    users:(("server",pid=1665474,fd=9))     
LISTEN 0      1024         0.0.0.0:12345       0.0.0.0:*    users:(("client",pid=1668470,fd=10))
```


In general this is more or less what it looks like. Note that the packet capture originates from `client` and is proxied into `server` before reaching its final destination. Technically it works like a tunnel.


![image](/assets/img/posts/2023/01/f3b4ff3ccb064757b6340b0838f2c2a9fb31cbcf681af01f9e3538e2f8273854.png)


The proxy may be tested with, for example, cURL to inspect how it handles incoming connections and how it forwards to server:

- `curl -v -x socks5://127.0.0.1:12345 https://vrls.ws`



## Decrypting the traffic 1

Digging a little bit deeper analyzing the `client` binary statically we find out some interesting things.


![image](/assets/img/posts/2023/01/0eff8a15d3574771f089793b8fbe97c512c1624c2f780fd7f90ba2561ed2e2a9.png)


After all the tokio runtime stuff has been initialized we reach the `client::main` function where the actual program begins. 

One of the first things to do before the client starts listening and forwarding TCP to the server, is loading the configurations from a YAML string embedded in the executable because there is no additional file. So we see a call to `serde_yaml::from_str` that parses the following YAML string:


![image](/assets/img/posts/2023/01/9cd0c0a9ad7fd73009e52a888e05df8569e71e9cbeebf113740231614e55fb29.png)


This is part of a RSA PUBLIC KEY. Extracting the whole string from `client` gives us the following string:


<!-- 
```yaml
pubkey: |
    -----BEGIN RSA PUBLIC KEY----
    MIIBCgKCAQEA231sNrX6WxlQpfsy8u6VR9rw4H4lY93fspAmXefjDhQhYCPM+Syp
    BvIgb/w9f8AGkEwUlDQxfZCClz72GAuS9jrlsqg9LpSMZ+PJAO0BDWissJCJtyyE
    NW/9VVPpJLA0SSeYuTYJ84WDAcjsb0T++V97TXlSiq9svXt16LDxCQJjRXv9O1UT
    BkDpGGZmnR4xLiQT+Px6KOqAsrJcAF0EJaji5aBfHVQdrXQwgmq8PEsfnvp2iQCL
    Z2iDPLlGbRahdFeigXXT4L6UvjpbFr/9INvDb2+vQkRl7zlHVtUAMR4X5smW2nHH
    H5YyTi1cOvMFsN+oPGxgBGpSqYCxmPwINwIDAQAB
    -----END RSA PUBLIC KEY-----

mkey: explorer

privkey: |
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC93GDINPM6HX2+
    NN3bCznyri2rDHDVcamzA/rPDXi9Mb2hu1Ypqek4km/kf4MKDsrOU/3T5mcdx5kA
    80s7mBWlGaItg/sy6dsh2XOoKVEHcZYyrbSAbkYrT9CoLLM/JlipbsalKenkW9Jl
    HB0h+vwv/rAwXJ9IMSc4RQkvjn/QKuBPhcXfrfaAIKNO0L+iqUL3asFM2CF8DXZX
    y8pLAxMy2PDJLtb0I/rXDWRImWlBcIWBrhg7lDA0UxWXDD1i5MmMlvxmyho1F8Br
    h7ietK3XW7LWshD2ARIDgPoTZ7lZm7P9JbKSN+Uk7fay6LdkJXYszfT89Owmi7tm
    fUQ41fcBAgMBAAECggEAWyGJru+Dg/Sd44t6peY4lVy3fO/GxRz+qHeTjojX2HAk
    ppnGHM96q3XWkWYHHu/Ets6n+msQOcIRldwx01QHp6yrJI/CJkkLrq6yjhfu1dTW
    lFK+XhsQQT/ZVq/GBdzBF+qdHLAGnV7ZmUCqVyIipGLqbPw4VC2Ltr2kUBhlDySA
    A+gCnUrPyVi6O9OFcyDepKMy481gZLLijakINejYrsbdCInz2omHq12w/50tuFt1
    s4XMWJN+AW0g1Hx+tTk2jDX1Wqg/htmJhjGqTj02GLJ/CJQjRodEdA7mx3HGwhis
    igeZgHTdPgP1B5Z9NXwUg9Qxln72D4mGhLCGYcw8VQKBgQD6+oltv1i44BO/ROUJ
    kZPTLWeoBrxP2OOli4aOSilLifeGrUQOSUtvcFHOxzy5RrhvX89f3GnklXcGyHXD
    03wg0/hqL0HM1EzNLmWkJW0Ng5WRFFgfcQIKbWBK9SHhAmKzkHtZPq6NwN8MbZUF
    vndxDtcSOdH0/TbMtCMYYs0MswKBgQDBqM7QxWT6qebCU4YOV+5uwnP+hAunsWkv
    VW7pHgiPnZ8ARRZ9iFIqqiVRvKeeyZBEK22eOJNguz6Cqfz2451D/AHA7sXht+1D
    9GCE/ebvUw+lPNQIRKkAgwQ8Dx+R6ikaUGzUKYhmWYJ5xgS9ZALZ+k4+rSjFg9jV
    jFjT7xQvewKBgHo9bJI3kE77VKLkO2ndrdI9Wy9LmIyLZtVKj87d8B8Ko7TEz1Dm
    AgfU/QNppvnWqB4W3DokcK8U3VRAbptidiLHG0ccnT/WZ1HIN1kroWHjpQV0kzc9
    I3FQtIXNvyKItuoehPWCwiHovrqe5OZXTnWSdM47uzdH3Vj2o+FMvfJhAoGAQvus
    bTGZd8oEcvqIx7VKVy0TCdmKXnpSs3iNYDxvIZ2XPXSoDst0ACXRuq/SGm4FZE7R
    H4TaFP8u4+sAADVCVB16Tc1IzIXdnz+LkvRvSCAmrTSY8jMtcWvfrxZcCRBBH0Tq
    H4guEZisNIp1YTySb+rP3YXvMEImYdalcsii5rkCgYEAimnWJ5aFN3TDt3h76CL3
    nRQegnzekJBjXZfcrHdExkgNChWjiz+WU/FW/Z87xMxtfIEwwzzIQHxbKZhgzO/U
    p2eXdqH59DvauggbiS3h4p9k2kxWTocztarvdftMW0ncmA4yCKiUQEmWD784JCyx
    OupNNfr2rgViWggVBEtJUIg=
    -----END PRIVATE KEY-----

(...)can not parse yaml 127.0.0.1:8888 0.0.0.0:12345(...) 
```

-->


```yaml
pubkey: |
    -----BEGIN RSA PUBLIC KEY----
    MIIBCgKCAQEA231sNrX6WxlQpfsy8u6VR9rw4H4lY93fspAmXefjDhQhYCPM+Syp
    (..)
    H5YyTi1cOvMFsN+oPGxgBGpSqYCxmPwINwIDAQAB
    -----END RSA PUBLIC KEY-----

mkey: explorer

privkey: |
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC93GDINPM6HX2+
    (..)
    p2eXdqH59DvauggbiS3h4p9k2kxWTocztarvdftMW0ncmA4yCKiUQEmWD784JCyx
    OupNNfr2rgViWggVBEtJUIg=
    -----END PRIVATE KEY-----

# additional strings without null terminator (Rust 🤯)
can not parse yaml 127.0.0.1:8888 0.0.0.0:12345 ...
```


The public key on `client` should belong to `server` and vice-versa (assymetric key cryptography). Note there is an additional value for `mkey`.

Going further on `client::main` we find some references to `TcpStream::connect` and `lib::protocol::rc4`. In resume, this function is responsible for handling TCP streams RC4 encryption & decryption. 

![image](/assets/img/posts/2023/01/ee6463a667a064f675882994049a49f899838577c30b584ae98d5308fb574320.png)
 


By placing few breakpoints in the context of `process_transfer` function we can read the RC4 `key` from memory and it does match the `mkey` value from YAML file:

- `explorer` is the key to RC4 encrypt and decrypt.

![image](/assets/img/posts/2023/01/227fadfa5b16354ba4edf9ec32aa34917a07adc641ccc335cd066ef847fee63f.png)


![image](/assets/img/posts/2023/01/7a2539e9899ce3b431e38d4b44d54f76bf59bcc2eeddfb9256635c2c299b8cf5.png)


Note the decrypted data is still unreadable. Since we know there are RSA keys it means it could have additional layers of encryption. However, there are some leading zeroes visible at the beginning of the RC4 decrypted data.

![image](/assets/img/posts/2023/01/81130eca7c288f8ff8e1cc5fa67d010a31d36456c2336ffc81e0bc656e2af944.png)

If we start by splitting each 4 bytes we can observe a pattern:

```
00000008 00000000 00000000 00000008 00000000 00000001 00000048 00000001 00000000 01001db2ee547837c2b0394f9316a3c672109c854769d9627ce715aa82ae76af4fc7d468903ffa4f7c77 (...)
```

After splitting the "metadata" (fields with a lot of zeroes) from the actual data and aligning them it looks like the following:

![image](/assets/img/posts/2023/01/5a1aa5a9aee61b7df52397848d096ea9162409c70db1b97de98325d9249a4cce.png)



In order to really understand what those values preceding the actual message mean we should look at what is being written into and read from sockets.


## Demuxing TCP streams


The first value is the *length* of everything succeeding. For example:

- `00000008 | 00000000 00000000` means there are `0x08 = 8 bytes`
- `0000000a | 00000001 00000000 b30c` means there `0x0a = 10 bytes` to be read and so on


However there are still two unknown fields (the 2nd and 3rd column). 

At the very beginning of `client::process_connection`, whenever the `client` receives an incoming connection and before forwarding to the server, its capable of doing multiplexing. This means multiple users may use the `client` simultaneously while it do use the same established connection with the `server`. other words, multiple client requests are tunneled over the same client-server connection and there must be a way to handle them in order to deliver the responses to the correct users: `lib::protocol::mux`.


In the following image we may observe the `id` being mapped into a `stream`, stored in a `HashMap` and then being incremented by 1 for a future stream:

![image](/assets/img/posts/2023/01/e2974e4a9da4a3c36eb12a64802ea50d0a3b2f293d17cb31b092d02de2fedcf4.png)


If we perform multiple cURL requests for example, each one will have a distinct stream `id` and the value is reflected on the 3rd header field to keep track of which stream belongs to which user:

```text
$ curl -kv -x socks5://127.0.0.1:12345 https://vrls.ws --connect-timeout 999999 & \
curl -kv -x socks5://127.0.0.1:12345 https://vrls.ws --connect-timeout 999999 & \
curl -kv -x socks5://127.0.0.1:12345 https://vrls.ws --connect-timeout 999999 &
```

Example after demuxing by `stream_id` (3rd header value): 

![image](/assets/img/posts/2023/01/78549ce356de6757b0397d6eee2fae6b09d4ac126d11dcf0aa4e9da748341ee6.png)



Regarding the 2nd header after demuxing we can see it has basically three distinct values: `0, 1 and 2` translate to:

- `0: new connection`
- `1: in progress/transferring data`
- `2: transfer completed`


![image](/assets/img/posts/2023/01/cd5fe1835edf6fb1508ced3631eca7035f9336ac6316251636bbadeeaeeb0911.png)



### TLDR

- Protocol: `length (4 bytes) + state (4 bytes) + stream_id (4 bytes) + message (x bytes)`



## Key exchange

Another important step before decrypting the transmitted message is to find out the actual key. RSA is used to perform a key exchange between the client & server that is further used to encrypt the stream.

It begins by initializing a random number generation utility `rand::rng::Rng::gen` and feeding into `rsa::key::RsaPublicKey::encrypt`. Basically it RSA-encrypts an array of 16 randomly generated bytes using `server` public key (the `server` does the same with `client` public key).


![image](/assets/img/posts/2023/01/76a7a7c0d2ea6b8e604d34859d5353c3a013dbb0c38db8f05d1d355fabf040a0.png)


We are able to inspect the 2048-bit ciphertext in memory during runtime.


![image](/assets/img/posts/2023/01/8d96270f37f802b9d04566d96c844453a9113b9de64ee5393d457f15e0b6c526.png)


For sanity check we grab the `server` private key that is embedded into the server executable and try to decrypt the ciphertext. As a result we see the plaintext matches the client generated 128-bit key.

![image](/assets/img/posts/2023/01/508a7e0c3c9eea68aee9519587099865e0a3585029072c787d842421fcde459f.png)



After the keys are exchanged they must be verified by both ends to ensure each one received the correct key in order to proceed to with communication. But first there is an additional operation that takes both keys (i.e. the key generated on client and the key received from server). It starts by zipping 16-byte arrays and then mapping XOR function to each pair resulting in a [session key](https://en.wikipedia.org/wiki/Session_key).

![image](/assets/img/posts/2023/01/787fb840b90c5266df966bf21e5f2cf2dab7a3f0fa48b641ceed4f5464dca6ac.png)

For example, suppose the client generated the key `133cb1a120196141af208b4d112f26c3` and received the server key `f41f823cc17a9a5bcf5d253cf6b8cea2`.
The result after zipping both keys and applying a XOR function to each item (tuples in this case) will be:

- 0x13 ^ 0xf4 = 0xe7
- 0x3c ^ 0x1f = 0x23
- and so on...

- Derived session key: `e723339de163fb1a607dae71e797e861`

The Python equivalent of this operation would be something like the following:

```python
client_key = bytes.fromhex('133cb1a120196141af208b4d112f26c3')
server_key = bytes.fromhex('f41f823cc17a9a5bcf5d253cf6b8cea2')
session_key = map(lambda x: x[0]^x[1], zip(client_key, server_key))
# e723339de163fb1a607dae71e797e861
```


When the session key has been derived both `client` and `server` calculate its respective SHA-256 hash digest (`openssl::sha::sha256`), exchange it and compare to ensure both have derived the same key.

![image](/assets/img/posts/2023/01/a385bc4316fdb5a3d6ff2399b77bd33e0472baba907e15df9eda7bf019eda834.png)




## Decrypting the traffic 2


From this point and considering all the steps we just went through it is trivial to decrypt the `pcap` contents. After the session key hash has been succesfully validated by both `client` and `server` it starts by encrypting with `AES-128-CBC` mode using the derivated key from the previous section.


![image](/assets/img/posts/2023/01/ce616521989a02ed1f32cb1e249f8efa2c3286d47c1a37b4cb5e836b75d02994.png)

Continuing the previous example and after getting the whole TCP stream from Wireshark we may try to decrypt using the parameters we found. 
Consider the following silly Python script to dump `client -> server` packets:

```python
# client -> server 
data = '0000000800000000000(...)200000000'

# server -> client
#data = '000000080000000000000000(...)200000000'

idx = 0
while idx < len(data):

    length = int(data[idx:idx+8],16)
    state = int(data[idx+8:idx+16],16)
    sid = int(data[idx+16:idx+24],16)

    messagae = data[idx+24:idx+24+2*length-8-8]
    print(length, state, sid, messagae)

    # move to next packet
    idx += length*2 + 8 
```

It will output the following results:

![image](/assets/img/posts/2023/01/cb42dd5e001580bb5c68077d84a297ebc29c79388ecf3c815b94469a01dbbfbd.png)


Some things we may observe in the protocol:

- The data from 7th line match the SHA256 hash we got during key exchange on previous example: `118d31c061936b811327f1645c9f8deef4c6628e3ee21b39950213ddd0cf2141`
- Everything after that line will probably be AES encrypted, while before that line will be RSA encrypted and related with key exchange.
- The message length from `2nd, 3rd, 4th and 5th` lines are respectively (64+64+64+64 = 256 bytes = 2048 bits = RSA key size)
- Note: there is an additional header for the length of RSA or AES ciphertexts which was not parsed properly by the script due to laziness to write a decent script.


![image](/assets/img/posts/2023/01/d6ffcf36935ec6a0bd3a23ab8286fb888e10dbd71e009e54373d42d1ecf974b9.png)


Now let's try to decrypt the data using the key we got previously and confirm it works! 


![image](/assets/img/posts/2023/01/3e35c1e1ecd9435b4d6cd508092fa474d1cae555581b1a3149d715b276c23b3e.png)



## Flag


To get the flag we just need to reproduce the same steps but using the actual `FLAG.pcap` from given for the challenge.  
   
- Must be repeated for both `client -> server` and `server -> client` packets


In resume:

1 - De-multiplex the streams (there are 4 distinct streams on `FLAG.pcap`)

![image](/assets/img/posts/2023/01/6d536acf461be58d3c9cfbe5d88ae1d48bdf4dc84116dbbf2d2d2049f2effdd2.png)



2 - Decrypt each key exchange with `server` private key and `client` private key respectively


![image](/assets/img/posts/2023/01/b63de2804b5ae61acdf235c9b62064a42d6a35d92b628f7ddd81befcbaf65fbf.png)



3 - Derive session key by XOR'ing both exchanged keys

- For **stream id \#3**  the keys are respectively:
    - `171c41af47c5340eff9aa3421b2a4cc8` & `859a42b1d67e8e864712d04b4ba56e06`
    - Session key: `9286031e91bbba88b8887309508f22ce`
    - (repeat for remaining streams...)

![image](/assets/img/posts/2023/01/64612c9116f7595f3468e1dd7c722fbc59b11eb1040d5e66a5e1cec021420806.png)



4 - Repeat and decrypt the remaining messages using AES-128-CBC mode with the derived key, per stream, until we eventually reach the flag


![image](/assets/img/posts/2023/01/dacb562dac253380411585a5ec7a70158e9cd696de443e3bb07b1e6380dd5e63.png)


- `rwctf{l1fe_1s_sh0rt_DO0_not_us3_rust}`


## Conclusion

Finally, in very generic terms and after several hours of reversing, the main program flow is similar to the following:

```rust
client::main
    serde_yaml::de::from_str (read YAML string config including RSA keys and RC4 key)

    tokio::net::tcp::stream::TcpStream::connect (connect to server)
    
    lib::protocol::rc4::Rc4::new (key: explorer, handle TCP data encryption/decryption)
    lib::protocol::rc4::Rc4::process_transfer
        lib::protocol::rc4::Rc4::process_data
            openssl::symm::Crypter::update

    lib::protocol::mux::MuxCore::new (initialize multiplex handler)
        std::collections::hash::map::HashMap (storage map id -> stream)

    lib::protocol::mux::MuxCore::process_transfer
        lib::protocol::mux::MuxCore::read_peer_dispatch

    tokio::net::tcp::listener::TcpListener::bind (listen on port :12345)
    tokio::net::tcp::listener::TcpListener::accept

    client::process_connection
        lib::protocol::mux::MuxInterface::get_stream
            std::collections::hash::map::HashMap::insert (map id -> stream)
            lib::protocol::mux::MuxChannel::new

        lib::protocol::mux::MuxChannel::connect (get into the correct channel)
        lib::protocol::mux::MuxChannel::process_transfer

        lib::protocol::crypto::Crypto::new 
            pkcs1::traits::DecodeRsaPublicKey::from_pkcs1_pem
            pkcs8::traits::DecodePrivateKey::from_pkcs8_pem

        lib::protocol::crypto::Crypto::key_exchange
            rand::rng::Rng::gen (generate random 16-bytes key)
            rsa::padding::PaddingScheme::new_pkcs1v15_encrypt (encrypt the key)
            tokio::io::util::async_write_ext::AsyncWriteExt::write_all
            tokio::io::util::async_read_ext::AsyncReadExt::read_exact
            rsa::padding::PaddingScheme::new_pkcs1v15_encrypt
            rsa::key::RsaPrivateKey::decrypt (decrypt the received key from the server)

            core::iter::adapters::zip::zip
            core::iter::traits::iterator::Iterator::map 
            core::iter::traits::iterator::Iterator::collect (map(xor, zip(key1, key2)))
            
            openssl::sha::sha256 (hash session_key to validate successful key exchange)
            tokio::io::util::async_write::AsyncWriteExt::write_all (send hash)
            tokio::io::util::async_read::AsyncReadExt::read_exact (receive hash and compare)

        lib::protocol::crypto::Crypto::process_transfer
            lib::protocol::crypto::Crypto::process_data_enc (process the actual connections)
                lib::protocol::crypto::Crypto::process_data_enc_in
                    openssl::symm::Cipher::aes_128_cbc (aes encrypt using session_key obtained)
                    tokio::io::util::async_read_ext::AsyncReadExt::read_buf
                    rand::rng::Rng::gen
                    openssl::symm::encrypt
                    tokio::io::util::async_write_ext::AsyncWriteExt::write_all_buf

```

Thanks to:
- zh-explorer (the challenge author)
- Nevsor (Sauercloud) for the hint

![image](/assets/img/posts/2023/01/ce64479bc08aa212e1abb234db48097bab7152dd4d192bc4a29de784b99cd351.png)



## References

- [https://realworldctf.com/](https://realworldctf.com/)
- [https://github.com/chaitin/Real-World-CTF-5th-Challenges/](https://github.com/chaitin/Real-World-CTF-5th-Challenges/)
- [https://blog.cryptohack.org/cracking-chinese-proxy-realworldctf](https://blog.cryptohack.org/cracking-chinese-proxy-realworldctf)
- [https://blog.csdn.net/sln_1550/article/details/128638427](https://blog.csdn.net/sln_1550/article/details/128638427)
- [https://en.wikipedia.org/wiki/Session_key](https://en.wikipedia.org/wiki/Session_key)
