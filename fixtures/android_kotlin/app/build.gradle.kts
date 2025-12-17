plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.luciq.android")
}

android {
    namespace = "com.example.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.app"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    implementation("com.luciq.library:luciq:14.2.0")
    implementation("com.luciq.library:luciq-ndk:14.2.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

luciq {
    appToken = "android-app-token-12345"
    uploadMappingFile = true
}
