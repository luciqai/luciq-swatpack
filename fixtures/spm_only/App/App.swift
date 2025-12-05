import Foundation

struct Demo {
    func setup() {
        Luciq.start(withToken: "demo", invocationEvents: [.shake, .screenshot])
        Luciq.setAutoMaskScreenshots([.textInputs])
        Luciq.identifyUser(withID: "user", email: "demo@example.com", name: "Demo")
        Luciq.setBugReportingEnabled(true)
        Luciq.setCrashReportingEnabled(true)
        Luciq.setSessionReplayEnabled(false)
        Luciq.setSurveysEnabled(false)
        Luciq.setFeatureRequestsEnabled(true)
        Luciq.setRepliesEnabled(true)
        CrashReporting.oomEnabled = false
        Luciq.setAPMEnabled(true)

        BugReporting.setAttachmentTypesEnabled(
            true,
            extraScreenshot: false,
            galleryImage: true,
            voiceNote: true,
            screenRecording: false
        )

        Luciq.addFeatureFlag("NewCheckoutFlow", variant: "enabled")
        Luciq.show()
        Luciq.log("Invoked Luciq manually from diagnostics")
        Luciq.setCustomData("tier", value: "beta")

        NetworkLogger.setRequestObfuscationHandler { request in
            var mutableRequest = request
            mutableRequest.setValue("*****", forHTTPHeaderField: "Authorization")
            mutableRequest.setValue("*****", forHTTPHeaderField: "Cookie")
            return mutableRequest
        }
    }

    func logout() {
        Luciq.removeAllFeatureFlags()
        Luciq.logOut()
    }
}
