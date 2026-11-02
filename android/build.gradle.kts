// The Chaquopy plugin is deliberately NOT declared here: it must be declared in app/build.gradle.kts so its
// runtime configuration belongs to the :app project. Declared here (apply false) it belongs to the root project
// and the Kotlin compile task fails with "Current thread does not hold the state lock for root project".
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.0" apply false
}
