import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.8.0"
    id("com.diffplug.spotless") version "5.12.1"
}

repositories {
    mavenCentral()
}

description = "A packaged version of the scripts in https://github.com/sepehrdaddev/zap-scripts"

val scriptsDir = layout.buildDirectory.dir("scripts")

zapAddOn {
    addOnId.set("sepehrdadscripts")
    addOnName.set("Sepehrdad Scripts")
    zapVersion.set("2.11.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    releaseLink.set("https://github.com/sepehrdaddev/zap-scripts/compare/v@PREVIOUS_VERSION@...v@CURRENT_VERSION@")
    unreleasedLink.set("https://github.com/sepehrdaddev/zap-scripts/compare/v@CURRENT_VERSION@...HEAD")

    manifest {
        author.set("Sepehrdad")
        url.set("https://www.zaproxy.org/docs/desktop/addons/sepehrdad-scripts/")
        repo.set("https://github.com/sepehrdaddev/zap-scripts/")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        files.from(scriptsDir)
    }
}

var scriptTypes = listOf(
        "active")

val syncScriptsDirTask by tasks.creating(Sync::class) {
    into(scriptsDir.get().dir(project.name))

    scriptTypes.forEach {
        from(it) {
            into(it)
        }
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

sourceSets["main"].output.dir(mapOf("builtBy" to syncScriptsDirTask), scriptsDir)

spotless {
    java {
        licenseHeaderFile("$rootDir/gradle/spotless/license.java")

        googleJavaFormat("1.7").aosp()
    }

    kotlinGradle {
        ktlint()
    }
}
