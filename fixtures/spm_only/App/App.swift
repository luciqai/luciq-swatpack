import Foundation

struct Demo {
    func setup() {
        Luciq.start(withToken: "demo", invocationEvents: [.shake, .screenshot])
        Luciq.setAutoMaskScreenshots([.textInputs])
        Luciq.identifyUser(withID: "user", email: nil, name: nil)
        Luciq.logOut()
    }
}
