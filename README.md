# Swiftsonver
> A CLI tool to create a full mock REST API with zero coding

![](https://img.shields.io/badge/license-Apache--2.0-brown)
![](https://img.shields.io/badge/version-0.9.0-orange)
![](https://img.shields.io/badge/Vapor-4.92.4-purple)
![](https://img.shields.io/badge/Yams-5.0.6-red)
![](https://img.shields.io/badge/Commander-0.9.2-green)
![](https://img.shields.io/badge/Swift-5.9-blue)

## Installation

To install Swiftsonver, run the following commands:

### For macOS :
```bash
cd ~/Downloads
wget https://github.com/YassineLafryhi/Swiftsonver/releases/download/0.9.0/Swiftsonver.zip
unzip Swiftsonver.zip
sudo mkdir -p /usr/local/bin
sudo mv swiftsonver /usr/local/bin/swiftsonver
sudo chmod +x /usr/local/bin/swiftsonver
```

## Configuration

Start by running `swiftsonver init` file inside your project directory, then edit the **swiftsonver.yml** file :

```yml
apiVersion: "v1"
jsonDatabaseName: "database.json"
publicFolderName: "public"
uploadsFolderName: "uploads"
requiresAuthorization: true
jwtSecret: "MY_JWT_SECRET"
jwtExpirationTime: 300 # 5 minutes
adminUsername: "admin"
adminPassword: "password"
resources:
  - name: "posts"
  - name: "comments"
```

## Usage
After editing the **swiftsonver.yml** file, run the following command to start the server:
```shell
swiftsonver serve
```
  
## How to build

To build Swiftsonver from source, run the following commands:

```shell
git clone https://github.com/YassineLafryhi/Swiftsonver.git
cd Swiftsonver
chmod +x build.sh
./build.sh
# Then you can move swiftsonver to /usr/local/bin/swiftsonver
```

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
[Apache License 2.0](https://choosealicense.com/licenses/apache-2.0)

