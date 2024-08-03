plugins {
    kotlin("jvm") version "2.0.0"
    application
}

group = "rencfs-kotlin"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation(kotlin("rencfs-kotlin"))
}

application {
    mainClass.set("MainKt")

    // Set JVM arguments
    applicationDefaultJvmArgs = listOf("-Djava.library.path=../kotlin-bridge/target/release/")
}

tasks.named<JavaExec>("run") {
    // Set application arguments
    args = listOf("/home/gnome/rencfs", "/home/gnome/rencfs_data", "a")
}
tasks.test {
    useJUnitPlatform()
}