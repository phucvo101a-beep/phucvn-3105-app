import Foundation

enum ExploitSupportPolicy {
    static let verifiedIOS15Range = "15.0–15.8.x"
    static let verifiedIOS16Range = "16.0–16.7.x"
    static let verifiedIOS17Range = "17.0–17.7.x"
    static let verifiedIOS18Range = "18.0–18.7.10"
    static let verifiedIOS26Range = "26.0–26.6.1"
    static let verifiedIOS27Range = "27.0–27.2.x"

    static let verifiedIOS27Builds: [(beta: Int, publicBeta: Int?, build: String)] = [
        (1, nil, "24A5355q"),
        (2, nil, "24A5370h"),
        (3, 1, "24A5380h"),
        (4, 2, "24A5390f")
    ]

    static func iOS27BetaNumber(for build: String) -> Int? {
        verifiedIOS27Builds.first { $0.build == build }?.beta
    }

    static func iOS27PublicBetaNumber(for build: String) -> Int? {
        verifiedIOS27Builds.first { $0.build == build }?.publicBeta
    }

    static func supportsKernelExploit(major: Int, minor: Int, patch: Int) -> Bool {
        guard minor >= 0, patch >= 0 else { return false }

        if major == 15 || major == 16 {
            return true
        }

        if major == 17 {
            return minor <= 7
        }

        if major == 18 {
            return true
        }

        if major == 26 {
            return minor < 6 || (minor == 6 && patch <= 1)
        }

        if major == 27 {
            return minor <= 2
        }

        return false
    }

    static func isSupported(major: Int, minor: Int, patch: Int, build: String) -> Bool {
        if major >= 15 && major <= 27 {
            if major == 27 {
                return minor <= 2
            }
            return true
        }

        return false
    }
}
