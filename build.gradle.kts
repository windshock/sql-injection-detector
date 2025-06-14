plugins {
    kotlin("jvm") version "1.9.0"
    id("antlr")
    `maven-publish`
}

kotlin {
    jvmToolchain(8)
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

group = "com.windshock.security"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.7.22")
    implementation("org.springframework.boot:spring-boot-starter-data-r2dbc:2.3.3.RELEASE")
    implementation("org.springframework.boot:spring-boot-starter-webflux:2.3.3.RELEASE")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions:1.0.1.RELEASE")
    implementation("io.r2dbc:r2dbc-h2:1.0.0.RELEASE")
    implementation("io.r2dbc:r2dbc-pool:0.8.3.RELEASE")
    testImplementation("io.projectreactor:reactor-test:3.3.9.RELEASE")
    testImplementation("org.springframework.boot:spring-boot-starter-test:2.3.3.RELEASE")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.jetbrains.kotlin:kotlin-reflect:1.7.22")
    antlr("org.antlr:antlr4:4.13.2")
}


// ANTLR code generation options are specified in a separate task
tasks.named<org.gradle.api.plugins.antlr.AntlrTask>("generateGrammarSource") {
    arguments = listOf("-visitor", "-long-messages")
}

tasks.test {
    useJUnitPlatform()
}

sourceSets["main"].java.srcDir("build/generated-src/antlr/main")

tasks.named("compileTestKotlin") {
    dependsOn("generateTestGrammarSource")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}
