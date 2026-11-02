plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python")
}

android {
    namespace = "hu.speeder.mute"
    compileSdk = 35

    defaultConfig {
        applicationId = "hu.speeder.mute"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.2.1"
        ndk {
            // Chaquopy 17 ships Python 3.12 only for these two ABIs (no 32-bit ARM).
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    packaging {
        // tor and the pluggable transports are executables shipped as lib*.so: they must be
        // unpacked to the native library directory so Python can start them as processes.
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

// Resolved now, at configuration time: Chaquopy evaluates the pip block later, where project state is off limits.
val wheelsDir: String = layout.projectDirectory.dir("../wheels").asFile.absolutePath

chaquopy {
    defaultConfig {
        version = "3.12"
        pip {
            // stem is published on PyPI as a source archive only; Chaquopy needs wheels, so one is kept in android/wheels.
            options("--find-links", wheelsDir)
            install("cryptography>=42")
            install("noiseprotocol>=0.3.1")
            install("stem>=1.8")
            install("PySocks>=1.7")
        }
    }
    sourceSets {
        getByName("main") {
            srcDir(layout.buildDirectory.dir("mute-python"))
        }
    }
}

// mute.py (repo root) is used unchanged; android/python holds only the bridge.
val syncMutePython = tasks.register<Copy>("syncMutePython") {
    from(rootProject.file("../mute.py"))
    from(rootProject.file("python")) { exclude("__pycache__/**") }
    into(layout.buildDirectory.dir("mute-python"))
}
tasks.named("preBuild") { dependsOn(syncMutePython) }
// Chaquopy's merge/requirements tasks read the copied sources: tell Gradle they must run after the copy.
tasks.configureEach {
    if (name != "syncMutePython" && name.contains("Python")) dependsOn(syncMutePython)
}

dependencies {
    val torVer = providers.gradleProperty("torAndroidVersion").get()
    val obfsVer = providers.gradleProperty("obfs4ProxyAndroidVersion").get()
    val snowVer = providers.gradleProperty("snowflakeAndroidVersion").get()
    implementation("org.briarproject:tor-android:$torVer")
    implementation("org.briarproject:obfs4proxy-android:$obfsVer")
    implementation("org.briarproject:snowflake-android:$snowVer")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.foundation:foundation")
}
