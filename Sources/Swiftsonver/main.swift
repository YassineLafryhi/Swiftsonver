import Commander
import JWT
import Logging
import Vapor
import Yams

enum ANSIColor: String {
    case black = "\u{001B}[0;30m"
    case red = "\u{001B}[0;31m"
    case green = "\u{001B}[0;32m"
    case yellow = "\u{001B}[0;33m"
    case blue = "\u{001B}[0;34m"
    case magenta = "\u{001B}[0;35m"
    case cyan = "\u{001B}[0;36m"
    case white = "\u{001B}[0;37m"
    case reset = "\u{001B}[0m"
    case teal = "\u{001B}[38;5;6m"
}

enum TextStyle {
    case normal
    case bold
}

func doesTerminalSupportANSIColors() -> Bool {
    guard isatty(fileno(stdout)) != 0 else {
        return false
    }
    if let termType = getenv("TERM"), let term = String(utf8String: termType) {
        let supportingTerms = ["xterm-color", "xterm-256color", "screen", "screen-256color", "ansi", "linux", "vt100"]
        return supportingTerms.contains(where: term.contains)
    }
    return false
}

func printInColors(_ message: String, color: ANSIColor = .blue, style: TextStyle = .bold) {
    if doesTerminalSupportANSIColors() { _ = style == .bold ? ";1m" : "m"
        let coloredMessage =
            "\(color.rawValue)\(style == .bold ? color.rawValue.replacingOccurrences(of: "[0;", with: "[1;") : color.rawValue)\(message)\(ANSIColor.reset.rawValue)"
        print(coloredMessage)
    } else {
        print(message)
    }
}

struct AppConfig: Codable {
    var hostname: String
    var port: Int
    var apiVersion: String
    var jsonDatabaseName: String
    var publicFolderName: String?
    var uploadsFolderName: String?
    var requiresAuthorization: Bool
    var jwtSecret: String?
    var jwtExpirationTime: Int?
    var adminUsername: String?
    var adminPassword: String?
    var resources: [Resource]
}

struct Resource: Codable {
    var name: String
}

func loadAppConfig() throws -> AppConfig? {
    let fileName = "swiftsonver.yml"
    let currentPath = FileManager.default.currentDirectoryPath
    let filePath = "\(currentPath)/\(fileName)"

    guard FileManager.default.fileExists(atPath: filePath) else {
        printInColors("Configuration file 'swiftsonver.yml' not found at \(filePath)", color: .red, style: .bold)
        exit(1)
    }

    let contents = try String(contentsOfFile: filePath)
    let decoder = YAMLDecoder()
    let config = try decoder.decode(AppConfig.self, from: contents)

    let jsonDatabasePath = "\(currentPath)/\(config.jsonDatabaseName)"
    if !FileManager.default.fileExists(atPath: jsonDatabasePath) {
        try createJSONDatabase(config: config, path: jsonDatabasePath)
    }

    if let publicFolderName = config.publicFolderName {
        let publicFolderPath = "\(currentPath)/\(publicFolderName)"

        if !FileManager.default.fileExists(atPath: publicFolderPath) {
            do {
                try FileManager.default.createDirectory(atPath: publicFolderPath, withIntermediateDirectories: true)
            } catch {
                print("Error creating \(publicFolderName) folder: \(error)")
            }
        }
    }

    if let uploadsFolderName = config.uploadsFolderName {
        let uploadsFolderPath = "\(currentPath)/\(uploadsFolderName)"
        if !FileManager.default.fileExists(atPath: uploadsFolderPath) {
            do {
                try FileManager.default.createDirectory(atPath: uploadsFolderPath, withIntermediateDirectories: true)
            } catch {
                print("Error creating \(uploadsFolderName) folder: \(error)")
            }
        }
    }

    return config
}

func createJSONDatabase(config: AppConfig, path: String) throws {
    let database: [String: Any]

    if
        config.requiresAuthorization,
        let adminUsername = config.adminUsername,
        let adminPassword = config.adminPassword
    {
        database = try [
            "resources": config.resources.map { ["resource": $0.name, "items": []] },
            "users": [
                [
                    "username": adminUsername,
                    "password": Bcrypt.hash(adminPassword)
                ]
            ]
        ]
    } else {
        database = [
            "resources": config.resources.map { ["resource": $0.name, "items": []] }
        ]
    }

    let data = try JSONSerialization.data(withJSONObject: database, options: [.prettyPrinted])
    FileManager.default.createFile(atPath: path, contents: data, attributes: nil)
}

func loadDatabase(from: String) throws -> [String: Any] {
    let fileURL = URL(fileURLWithPath: from)
    let data = try Data(contentsOf: fileURL)
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw Abort(.internalServerError, reason: "Failed to decode database.json")
    }
    return json
}

func saveDatabase(to: String, _ database: [String: Any]) throws {
    let fileURL = URL(fileURLWithPath: to)
    let data = try JSONSerialization.data(withJSONObject: database, options: [.prettyPrinted])
    try data.write(to: fileURL)
}

struct EndpointConfig: Codable {
    var endpoints: [Endpoint]
}

struct Endpoint: Codable {
    var path: String
    var method: String
    var response: String
}

func watchFile(_: String, app _: Application, appConfig _: AppConfig) {
    /* let fileURL = URL(fileURLWithPath: path)
     let fileDescriptor = open(fileURL.path, O_EVTONLY)
     let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fileDescriptor, eventMask: .write, queue: DispatchQueue.global())
     source.setEventHandler {
         // print("File changed: \(path)")
         do {
             let json = try loadDatabase(from: path)
             let resources = json["resources"] as? [[String: Any]]
             try routes(app, with: resources, jsonDatabasePath: path, appConfig: appConfig)
         } catch {
             printInColors("Error loading database: \(error)", color: .red, style: .bold)
         }
     }
     source.resume() */
}

struct Payload: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case expiration = "exp"
        case isAdmin = "admin"
    }

    var subject: SubjectClaim
    var expiration: ExpirationClaim
    var isAdmin: Bool
    func verify(using _: JWTSigner) throws {
        try expiration.verifyNotExpired()
    }
}

func routes(_ app: Application, with: [[String: Any]]?, jsonDatabasePath: String, appConfig: AppConfig) throws {
    if
        appConfig.requiresAuthorization,
        let adminUsername = appConfig.adminUsername,
        let adminPassword = appConfig.adminPassword,
        let jwtExpirationTime = appConfig.jwtExpirationTime
    {
        app.post("login") { req -> Response in
            let body = try req.content.decode([String: String].self)
            let username = body["username"]!
            let password = body["password"]!
            let database = try loadDatabase(from: jsonDatabasePath)
            if let users = database["users"] as? [[String: String]] {
                let user = users.first(where: { $0["username"] == username })
                if user == nil {
                    throw Abort(.unauthorized, reason: "Invalid username or password")
                }
                if let hashedPassword = user?["password"] {
                    if try Bcrypt.verify(password, created: hashedPassword) {
                        let expirationTime = Date().addingTimeInterval(TimeInterval(jwtExpirationTime))
                        let payload = Payload(
                            subject: "Swiftsonver",
                            expiration: .init(value: expirationTime),
                            isAdmin: true)
                        let response = try ["token": req.jwt.sign(payload)]
                        let data = try JSONSerialization.data(withJSONObject: response, options: [])
                        return Response(
                            status: .ok,
                            headers: ["Content-Type": "application/json"],
                            body: Response.Body(data: data))
                    } else {
                        throw Abort(.unauthorized, reason: "Invalid username or password")
                    }
                } else {
                    throw Abort(.unauthorized, reason: "Invalid username or password")
                }
            } else {
                throw Abort(.internalServerError, reason: "Users format is incorrect")
            }
        }
    }

    app.post("register") { req -> HTTPStatus in
        let body = try req.content.decode([String: String].self)
        let username = body["username"]!
        let password = body["password"]!
        var database = try loadDatabase(from: jsonDatabasePath)
        if var users = database["users"] as? [[String: String]] {
            if users.first(where: { $0["username"] == username }) != nil {
                throw Abort(.badRequest, reason: "Username already exists")
            }
            try users.append(["username": username, "password": Bcrypt.hash(password)])
            database["users"] = users
            try saveDatabase(to: jsonDatabasePath, database)
            return .ok
        } else {
            throw Abort(.internalServerError, reason: "Users format is incorrect")
        }
    }

    if let uploadsFolderName = appConfig.uploadsFolderName {
        app.post("upload") { req -> EventLoopFuture<HTTPStatus> in
            let uploadDirectory = "\(uploadsFolderName)/"
            let directory = req.application.directory.workingDirectory + uploadDirectory
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            let file = req.body.data
            // TODO: Add file extension
            let filename = "\(UUID().uuidString)"
            return req.fileio.writeFile(file!, at: "\(directory)\(filename)").map {
                .ok
            }
        }

        app.get("files", ":filename") { req -> Response in
            let filename = req.parameters.get("filename")!
            let uploadDirectory = "\(uploadsFolderName)"
            let directory = req.application.directory.workingDirectory + uploadDirectory
            let path = "\(directory)/\(filename)"
            return req.fileio.streamFile(at: path)
        }
    }

    app.group("api", "\(appConfig.apiVersion)") { api in
        if let resources = with {
            for resource in resources {
                if let name = resource["resource"] as? String {
                    api.get("\(name)") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        do {
                            let json = try loadDatabase(from: jsonDatabasePath)
                            guard let resources = json["resources"] as? [[String: Any]] else {
                                let error = "{\"error\": \"Error: Unable to find resources.\"".data(using: .utf8)
                                return Response(
                                    status: .ok,
                                    headers: ["Content-Type": "application/json"],
                                    body: Response.Body(data: error!))
                            }

                            if let index = resources.firstIndex(where: { $0["resource"] as? String == name }) {
                                let resource = resources[index]
                                if let jsonResponse = resource["items"] as? [[String: Any]] {
                                    let data = try JSONSerialization.data(withJSONObject: jsonResponse, options: [])
                                    return Response(
                                        status: .ok,
                                        headers: ["Content-Type": "application/json"],
                                        body: Response.Body(data: data))

                                } else {
                                    let error = "{\"error\": \"Error: Items not found for resource.\"".data(using: .utf8)
                                    return Response(
                                        status: .ok,
                                        headers: ["Content-Type": "application/json"],
                                        body: Response.Body(data: error!))
                                }
                            } else {
                                let error = "{\"error\": \"Error: Resource not found.\"".data(using: .utf8)
                                return Response(
                                    status: .ok,
                                    headers: ["Content-Type": "application/json"],
                                    body: Response.Body(data: error!))
                            }
                        } catch {
                            let error = "{\"error\": \"Error: \(error.localizedDescription)\"".data(using: .utf8)
                            return Response(
                                status: .ok,
                                headers: ["Content-Type": "application/json"],
                                body: Response.Body(data: error!))
                        }
                    }

                    api.get("\(name)", ":id") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        do {
                            let json = try loadDatabase(from: jsonDatabasePath)
                            guard let resources = json["resources"] as? [[String: Any]] else {
                                let error = "{\"error\": \"Error: Unable to find resources.\"".data(using: .utf8)
                                return Response(
                                    status: .ok,
                                    headers: ["Content-Type": "application/json"],
                                    body: Response.Body(data: error!))
                            }

                            if let index = resources.firstIndex(where: { $0["resource"] as? String == name }) {
                                let resource = resources[index]
                                if let items = resource["items"] as? [[String: Any]] {
                                    let id = req.parameters.get("id")!
                                    if let item = items.first(where: { $0["id"] as? String == id }) {
                                        let data = try JSONSerialization.data(withJSONObject: item, options: [])
                                        return Response(
                                            status: .ok,
                                            headers: ["Content-Type": "application/json"],
                                            body: Response.Body(data: data))
                                    } else {
                                        let error = "{\"error\": \"Error: Item not found.\"".data(using: .utf8)
                                        return Response(
                                            status: .ok,
                                            headers: ["Content-Type": "application/json"],
                                            body: Response.Body(data: error!))
                                    }
                                } else {
                                    let error = "{\"error\": \"Error: Items not found for resource.\"".data(using: .utf8)
                                    return Response(
                                        status: .ok,
                                        headers: ["Content-Type": "application/json"],
                                        body: Response.Body(data: error!))
                                }
                            } else {
                                let error = "{\"error\": \"Error: Resource not found.\"".data(using: .utf8)
                                return Response(
                                    status: .ok,
                                    headers: ["Content-Type": "application/json"],
                                    body: Response.Body(data: error!))
                            }
                        } catch {
                            let error = "{\"error\": \"Error: \(error.localizedDescription)\"".data(using: .utf8)
                            return Response(
                                status: .ok,
                                headers: ["Content-Type": "application/json"],
                                body: Response.Body(data: error!))
                        }
                    }

                    api.post("\(name)") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        var body = try req.content.decode([String: String].self)
                        var database = try loadDatabase(from: jsonDatabasePath)
                        if var resources = database["resources"] as? [[String: Any]] {
                            var updatedResources = false
                            for (index, resourceDict) in resources.enumerated() {
                                if let targetResource = resourceDict["resource"] as? String, targetResource == name {
                                    var items = resourceDict["items"] as? [[String: String]] ?? []
                                    let newId = UUID().uuidString
                                    body["id"] = newId
                                    items.append(body)
                                    resources[index]["items"] = items
                                    updatedResources = true
                                    break
                                }
                            }

                            if updatedResources {
                                database["resources"] = resources
                                try saveDatabase(to: jsonDatabasePath, database)
                                return Response(status: .ok)
                            } else {
                                throw Abort(.internalServerError, reason: "Resource not found")
                            }
                        } else {
                            throw Abort(.internalServerError, reason: "Resources format is incorrect")
                        }
                    }

                    api.put("\(name)", ":id") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        let body = try req.content.decode([String: String].self)
                        let id = req.parameters.get("id")!
                        var database = try loadDatabase(from: jsonDatabasePath)
                        if var resources = database["resources"] as? [[String: Any]] {
                            var updatedResources = false
                            for (index, resource) in resources.enumerated() {
                                if let targetResource = resource["resource"] as? String, targetResource == name {
                                    if var items = resource["items"] as? [[String: String]] {
                                        if let itemIndex = items.firstIndex(where: { $0["id"] == id }) {
                                            items[itemIndex] = body
                                            resources[index]["items"] = items
                                            updatedResources = true
                                            break
                                        }
                                    }
                                }
                            }

                            if updatedResources {
                                database["resources"] = resources
                                try saveDatabase(to: jsonDatabasePath, database)
                                return Response(status: .ok)
                            } else {
                                throw Abort(.internalServerError, reason: "Resource not found")
                            }
                        } else {
                            throw Abort(.internalServerError, reason: "Resources format is incorrect")
                        }
                    }

                    api.delete("\(name)", ":id") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        let id = req.parameters.get("id")!
                        var database = try loadDatabase(from: jsonDatabasePath)
                        if var resources = database["resources"] as? [[String: Any]] {
                            var updatedResources = false
                            for (index, resource) in resources.enumerated() {
                                if let targetResource = resource["resource"] as? String, targetResource == name {
                                    if var items = resource["items"] as? [[String: String]] {
                                        if let itemIndex = items.firstIndex(where: { $0["id"] == id }) {
                                            items.remove(at: itemIndex)
                                            resources[index]["items"] = items
                                            updatedResources = true
                                            break
                                        }
                                    }
                                }
                            }

                            if updatedResources {
                                database["resources"] = resources
                                try saveDatabase(to: jsonDatabasePath, database)
                                return Response(status: .ok)
                            } else {
                                throw Abort(.internalServerError, reason: "Resource not found")
                            }
                        } else {
                            throw Abort(.internalServerError, reason: "Resources format is incorrect")
                        }
                    }

                    api.delete("\(name)") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        var database = try loadDatabase(from: jsonDatabasePath)
                        if var resources = database["resources"] as? [[String: Any]] {
                            var updatedResources = false
                            for (index, resource) in resources.enumerated() {
                                if let targetResource = resource["resource"] as? String, targetResource == name {
                                    resources[index]["items"] = []
                                    updatedResources = true
                                    break
                                }
                            }

                            if updatedResources {
                                database["resources"] = resources
                                try saveDatabase(to: jsonDatabasePath, database)
                                return Response(status: .ok)
                            } else {
                                throw Abort(.notFound, reason: "Resource name not found")
                            }
                        } else {
                            throw Abort(.internalServerError, reason: "Resources format is incorrect")
                        }
                    }

                    api.patch("\(name)", ":id") { req -> Response in
                        if appConfig.requiresAuthorization {
                            let hasValidJWTToken = try req.hasValidJWTToken()
                            if !hasValidJWTToken {
                                throw Abort(.unauthorized)
                            }
                        }

                        let body = try req.content.decode([String: String].self)
                        let id = req.parameters.get("id")!
                        var database = try loadDatabase(from: jsonDatabasePath)
                        if var resources = database["resources"] as? [[String: Any]] {
                            var updatedResources = false
                            for (index, resource) in resources.enumerated() {
                                if let targetResource = resource["resource"] as? String, targetResource == name {
                                    if var items = resource["items"] as? [[String: String]] {
                                        if let itemIndex = items.firstIndex(where: { $0["id"] == id }) {
                                            items[itemIndex].merge(body) { _, new in new }
                                            resources[index]["items"] = items
                                            updatedResources = true
                                            break
                                        }
                                    }
                                }
                            }

                            if updatedResources {
                                database["resources"] = resources
                                try saveDatabase(to: jsonDatabasePath, database)
                                return Response(status: .ok)
                            } else {
                                throw Abort(.internalServerError, reason: "Resource not found")
                            }
                        } else {
                            throw Abort(.internalServerError, reason: "Resources format is incorrect")
                        }
                    }
                }
            }
        }
    }
}

extension Request {
    func hasValidJWTToken() throws -> Bool {
        guard let token = headers.bearerAuthorization?.token else {
            return false
        }
        do {
            let payload = try jwt.verify(token, as: Payload.self)
            // TODO: check roles, permissions
            return true
        } catch {
            printInColors("JWT Verification Error: \(error)", color: .red, style: .bold)
            return false
        }
    }
}

let serveCommand = command {
    var env = try Environment.detect()
    try LoggingSystem.bootstrap(from: &env)
    let appConfig = try loadAppConfig()
    let currentPath = FileManager.default.currentDirectoryPath
    let jsonDatabasePath = "\(currentPath)/\(appConfig!.jsonDatabaseName)"
    let json = try loadDatabase(from: jsonDatabasePath)

    let resources = json["resources"] as? [[String: Any]]

    let app = Application(env)
    app.http.server.configuration.hostname = appConfig?.hostname ?? "0.0.0.0"
    app.http.server.configuration.port = appConfig?.port ?? 8_080
    if let jwtSecret = appConfig?.jwtSecret {
        app.jwt.signers.use(.hs256(key: jwtSecret))
    }

    if let publicFolderName = appConfig?.publicFolderName {
        app.middleware.use(FileMiddleware(publicDirectory: "\(currentPath)/\(publicFolderName)"))
    }
    app.middleware.use(CORSMiddleware())

    watchFile(jsonDatabasePath, app: app, appConfig: appConfig!)
    defer { app.shutdown() }
    try routes(app, with: resources, jsonDatabasePath: jsonDatabasePath, appConfig: appConfig!)
    printInColors("Swiftsonver started successfully !", color: .green, style: .bold)
    try app.run()
}

let initCommand = command {
    let sampleConfig = """
        hostname: "0.0.0.0"
        port: 8080
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
        """

    let currentPath = FileManager.default.currentDirectoryPath
    let filePath = "\(currentPath)/swiftsonver.yml"

    do {
        try sampleConfig.write(toFile: filePath, atomically: true, encoding: .utf8)
        printInColors("swiftsonver.yml file has been created successfully.", color: .green, style: .bold)
    } catch {
        printInColors("Error creating swiftsonver.yml file: \(error)", color: .red, style: .bold)
    }
}

let main = Group {
    $0.addCommand("init", "Initialize a new swiftsonver.yml file with sample configuration.", initCommand)
    $0.addCommand("serve", "Start Swiftsonver.", serveCommand)
}

main.run()
