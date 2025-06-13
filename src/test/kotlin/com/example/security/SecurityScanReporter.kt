package com.example.security

import com.example.security.RiskLevel
import java.io.File
// import com.skplanet.pcona.console.repository.VulnerabilityReport // Uncomment if needed
// import com.skplanet.pcona.console.repository.RepositoryScanResult // Uncomment if needed

class SecurityScanReporter(private val results: List<RepositoryScanResult>) {
    private fun printVulnerabilitySource(v: VulnerabilityReport) {
        try {
            val filePath = try {
                val projectRoot = System.getProperty("user.dir")
                val sourceRoot = "$projectRoot/src/main/kotlin"
                val fullClassName = if (v.className.contains('.')) v.className else "com.example.repository.${v.className}"
                val className = fullClassName.replace('.', '/')
                val sourceFile = File("$sourceRoot/$className.kt")
                if (sourceFile.exists()) {
                    sourceFile.absolutePath
                } else {
                    // Fallback to class file location
                    val classLoader = Thread.currentThread().contextClassLoader
                    val resource = classLoader.getResource("$className.class")
                    if (resource != null) {
                        when (resource.protocol) {
                            "file" -> {
                                val classFile = File(resource.toURI())
                                val sourceFile = File(classFile.parentFile, "${classFile.nameWithoutExtension}.kt")
                                if (sourceFile.exists()) sourceFile.absolutePath
                                else "$sourceRoot/$className.kt"
                            }
                            "jar" -> {
                                val jarPath = resource.path.substring(0, resource.path.indexOf('!'))
                                val jarFile = File(jarPath.substring(5)) // Remove 'file:' prefix
                                val jar = java.util.jar.JarFile(jarFile)
                                val entry = jar.getEntry("$className.kt")
                                if (entry != null) {
                                    "jar:${jarFile.absolutePath}!/$className.kt"
                                } else {
                                    "$sourceRoot/$className.kt"
                                }
                            }
                            else -> "$sourceRoot/$className.kt"
                        }
                    } else {
                        "$sourceRoot/$className.kt"
                    }
                }
            } catch (e: Exception) {
                val projectRoot = System.getProperty("user.dir")
                val fullClassName = if (v.className.contains('.')) v.className else "com.example.repository.${v.className}"
                "$projectRoot/src/main/kotlin/${fullClassName.replace('.', '/')}.kt"
            }
            val file = java.io.File(filePath)
            if (!file.exists()) {
                println("      (Source file not found: $filePath)")
                return
            }
            val lines = file.readLines()
            // Find method start by signature
            val methodRegex = Regex("""fun\s+${Regex.escape(v.methodName)}\s*\(""")
            val methodIdx = lines.indexOfFirst { methodRegex.containsMatchIn(it) }
            if (methodIdx == -1) {
                println("      (Method definition not found: ${v.methodName})")
                return
            }
            // Print up to 15 lines of the method (or until next 'fun ')
            println("      ── Related code (File: $filePath, ${v.methodName}):")
            for (i in methodIdx until minOf(lines.size, methodIdx+15)) {
                val l = lines[i]
                if (i > methodIdx && l.trim().startsWith("fun ")) break
                println("      ${i+1}: ${l}")
            }
        } catch (e: Exception) {
            println("      (Code extraction error: ${e.message})")
        }
    }
    fun printReport() {
        val totalRepos = results.size
        val totalMethods = results.sumOf { it.totalMethods }
        // CRITICAL only count as vulnerable
        val vulnerableRepos = results.count { it.vulnerabilities.any { v -> v.riskLevel == RiskLevel.CRITICAL } }
        val totalVulnerabilities = results.sumOf { it.vulnerabilities.count { v -> v.riskLevel == RiskLevel.CRITICAL } }

        println("\n" + "=".repeat(60))
        println("🛡️  SQL INJECTION SECURITY SCAN REPORT")
        println("=".repeat(60))
        println("📊 Repositories scanned: $totalRepos")
        println("🔍 Methods analyzed: $totalMethods")
        println("⚠️  Vulnerable repositories: $vulnerableRepos")
        println("🚨 Total CRITICAL vulnerabilities found: $totalVulnerabilities")

        for (result in results) {
            val criticalByMethod = mutableMapOf<String, VulnerabilityReport>()
            val warningByMethod = mutableMapOf<String, VulnerabilityReport>()
            for (v in result.vulnerabilities) {
                if (v.riskLevel == RiskLevel.CRITICAL) {
                    val prev = criticalByMethod[v.methodName]
                    // Prefer [ParseTree] description if available
                    if (prev == null || (v.description.contains("[ParseTree]") && !prev.description.contains("[ParseTree]"))) {
                        criticalByMethod[v.methodName] = v
                    }
                }
            }
            if (criticalByMethod.isNotEmpty()) {
                println("\n📁 ${result.repositoryName}:")
                for ((_, v) in criticalByMethod) {
                    println("   🚨 [CRITICAL] ${v.methodName} - ${v.description}")
                    printVulnerabilitySource(v)
                }
            }
        }
        println("\n🔒 SECURITY RECOMMENDATIONS:")
        println("• Use parameterized queries with .bind() method")
        println("• Avoid string concatenation in SQL queries")
        println("• Use Spring Data query methods or @Query annotations")
        println("• Validate and sanitize all user inputs")
        if (totalVulnerabilities == 0) {
            println("\n✅ No SQL injection vulnerabilities detected!")
        }
        println("=".repeat(60))
    }

    fun getErrorMessage(): String {
        val vulnerableRepos = results.filter { it.hasVulnerabilities() }
        return buildString {
            append("❌ SQL INJECTION VULNERABILITIES DETECTED!\n")
            append("Vulnerable repositories: ${vulnerableRepos.joinToString { it.repositoryName }}\n")
            append("Total vulnerabilities: ${getTotalVulnerabilities()}\n")
            append("\nReview the scan report above for detailed information.")
        }
    }

    fun hasVulnerabilities(): Boolean = results.any { it.hasVulnerabilities() }
    fun getTotalVulnerabilities(): Int = results.sumOf { it.getVulnerabilityCount() }
}