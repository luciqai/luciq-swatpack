import Foundation

class PodsDemo {
    func configure() {
        Luciq.start(withToken: "demo", invocationEvents: [.floatingButton])
        NetworkLogger.setRequestObfuscationHandler { request in
            return request
        }
    }
}
