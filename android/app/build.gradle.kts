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

// mute.py (repo root, used unchanged) and android/python (the bridge + bundled stem) are copied into one
// source directory right here while the script is evaluated. No Gradle task is involved on purpose:
// copy tasks and task-graph hooks run lazily, which is where "state lock" errors come from.
val pythonSrcDir: File = layout.buildDirectory.dir("mute-python").get().asFile
pythonSrcDir.deleteRecursively()
pythonSrcDir.mkdirs()
layout.projectDirectory.file("../../mute.py").asFile.copyTo(File(pythonSrcDir, "mute.py"), overwrite = true)
layout.projectDirectory.dir("../python").asFile.copyRecursively(pythonSrcDir, overwrite = true)
pythonSrcDir.walkTopDown().filter { it.isDirectory && it.name == "__pycache__" }.toList()
    .forEach { it.deleteRecursively() }

chaquopy {
    defaultConfig {
        version = "3.12"
        pip {
            // stem is not installed from PyPI (it has no wheel): its source ships in android/python/stem.
            install("cryptography>=42")
            install("noiseprotocol>=0.3.1")
            install("PySocks>=1.7")
        }
    }
    sourceSets {
        getByName("main") {
            srcDir(pythonSrcDir)
        }
    }
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
