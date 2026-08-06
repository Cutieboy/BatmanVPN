plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.mousevpn.app"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "dev.mousevpn.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 5
        versionName = "0.1.4"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            // Internal MVP builds remain upgrade-compatible with the installed debug APK.
            // A separately protected production key is required before public distribution.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions.jvmTarget = "17"
}

val buildRust by tasks.registering(Exec::class) {
    val workspace = rootProject.projectDir.parentFile
    val output = project.layout.projectDirectory.dir("src/main/jniLibs")
    val userHome = System.getProperty("user.home")
    val cargo = System.getenv("CARGO") ?: "$userHome/.cargo/bin/cargo"
    val ndk = System.getenv("ANDROID_NDK_HOME")
        ?: "$userHome/Android/Sdk/ndk/27.0.12077973"
    workingDir(workspace)
    environment("ANDROID_NDK_HOME", ndk)
    commandLine(
        cargo,
        "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", output.asFile.absolutePath,
        "build", "--release", "-p", "mousevpn-android-native"
    )
}

tasks.named("preBuild").configure { dependsOn(buildRust) }
