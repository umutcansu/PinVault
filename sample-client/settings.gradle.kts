pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "SamplePinVaultClient"
include(":app")

// ── PinVault kütüphanesinin kaynağı ─────────────────────────────────────────
// gradle.properties → `pinvault.localPath` bir PinVault checkout'unu
// gösteriyorsa kütüphane o kaynaktan derlenir (composite build); henüz
// yayınlanmamış değişiklikler de dahil olur. Yol boşsa ya da checkout yoksa
// Maven Central'daki `pinvault.version` kullanılır.
//
// Tek seferlik Maven Central denemesi:  ./gradlew assembleDebug -Ppinvault.localPath=
val pinvaultLocalPath = providers.gradleProperty("pinvault.localPath").orNull?.trim().orEmpty()
if (pinvaultLocalPath.isNotEmpty()) {
    val checkout = file(pinvaultLocalPath)
    if (checkout.resolve("pinvault/build.gradle.kts").isFile) {
        includeBuild(checkout) {
            dependencySubstitution {
                substitute(module("io.github.umutcansu:pinvault")).using(project(":pinvault"))
            }
        }
        logger.lifecycle("PinVault: yerel kaynak kullanılıyor → ${checkout.canonicalPath}")
    } else {
        logger.warn(
            "PinVault: pinvault.localPath=$pinvaultLocalPath bir PinVault checkout'u değil; " +
                "Maven Central sürümü kullanılacak."
        )
    }
}
