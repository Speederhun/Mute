import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.chaquo.python") version "17.1.0"
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

    // Release signing comes from the environment (CI sets it from repository secrets). Without it the APK is signed
    // with the debug key so it still installs. A fixed key matters for updates: Android only updates an app in place
    // when the new APK is signed with the same key as the installed one.
    val releaseKeystore = System.getenv("MUTE_KEYSTORE")?.let { File(it) }
    signingConfigs {
        if (releaseKeystore != null && releaseKeystore.exists()) {
            create("mute") {
                storeFile = releaseKeystore
                storePassword = System.getenv("MUTE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("MUTE_KEY_ALIAS") ?: "mute"
                keyPassword = System.getenv("MUTE_KEY_PASSWORD") ?: System.getenv("MUTE_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("mute") ?: signingConfigs.getByName("debug")
        }
    }

    lint {
        checkReleaseBuilds = false
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

// Briar publishes tor, obfs4proxy and snowflake as plain JARs that carry the executables. Android Gradle does not turn
// native files inside a JAR into jniLibs, so they are unpacked here into <abi>/lib<name>.so and added as a jniLibs
// source. That puts them in the app's native library directory, the only place Android 10+ lets an app run a
// program from. Done at configuration time (like the python copy above) to avoid task-graph hooks.
val torJniDir: File = layout.buildDirectory.dir("tor-jni").get().asFile
run {
    torJniDir.deleteRecursively()
    torJniDir.mkdirs()
    val abis = setOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86")
    val listing = StringBuilder()
    for ((prop, artifact) in listOf(
        "torAndroidVersion" to "tor-android",
        "obfs4ProxyAndroidVersion" to "obfs4proxy-android",
        "snowflakeAndroidVersion" to "snowflake-android",
    )) {
        val ver = providers.gradleProperty(prop).get()
        val cfg = configurations.detachedConfiguration(dependencies.create("org.briarproject:$artifact:$ver"))
        cfg.isTransitive = false
        for (file in cfg.resolve()) {
            listing.append("== ").append(file.name).append('\n')
            ZipFile(file).use { zip ->
                for (e in zip.entries()) {
                    if (e.isDirectory || e.name.endsWith(".class") || e.name.startsWith("META-INF/")) continue
                    listing.append(e.name).append('\n')
                    val parts = e.name.split('/')
                    val abi = parts.firstOrNull { it in abis } ?: continue
                    if (abi !in setOf("arm64-v8a", "x86_64")) continue
                    var base = parts.last()
                    if (!base.startsWith("lib")) base = "lib$base"
                    if (!base.endsWith(".so")) base = "$base.so"
                    val out = File(torJniDir, "$abi/$base")
                    out.parentFile.mkdirs()
                    zip.getInputStream(e).use { input -> out.outputStream().use { input.copyTo(it) } }
                    // report the ELF segment alignment (Android 15 on 16 KB devices wants 0x4000 or more)
                    try {
                        val h = out.readBytes().let { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN) }
                        if (h.getInt(0) == 0x464c457f && h.get(4).toInt() == 2) {
                            val phoff = h.getLong(32).toInt(); val phentsize = h.getShort(54).toInt(); val phnum = h.getShort(56).toInt()
                            var align = 0L
                            for (i in 0 until phnum) {
                                val ph = phoff + i * phentsize
                                if (h.getInt(ph) == 1) align = maxOf(align, h.getLong(ph + 48))
                            }
                            logger.lifecycle("Tor file " + out.name + " (" + abi + "): segment alignment 0x" + align.toString(16) +
                                if (align >= 0x4000) " (16 KB ok)" else " (NOT 16 KB aligned)")
                        }
                    } catch (_: Exception) {}
                }
            }
        }
    }
    File(torJniDir, "LISTING.txt").writeText(listing.toString())
    if (!File(torJniDir, "arm64-v8a/libtor.so").exists()) {
        throw GradleException(
            "Could not find the Tor executable for arm64-v8a inside the Briar jars. Please send this list to the developer:\n" +
                listing.lines().take(80).joinToString("\n")
        )
    }
}

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

android.sourceSets.getByName("main").jniLibs.srcDir(torJniDir)

dependencies {
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
