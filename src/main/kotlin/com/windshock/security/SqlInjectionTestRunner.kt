package com.windshock.security

import kotlin.reflect.KClass
import kotlin.reflect.full.declaredFunctions
import kotlin.reflect.full.isSubclassOf
import kotlin.reflect.full.memberFunctions
import kotlin.reflect.jvm.jvmErasure
import org.springframework.context.ApplicationContext
// import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Import
//import org.springframework.boot.test.context.SpringBootTest
import com.windshock.security.TrackingDatabaseClientConfig
import com.windshock.security.DummyValueFactory
import com.windshock.security.SecurityScanReporter
import com.windshock.security.RepositoryScanResult
import com.windshock.security.SqlInjectionAstAnalyzer

/**
 * Public API for running SQL injection vulnerability scans.
 * This class is intended to be used in test classes to scan repositories for SQL injection vulnerabilities.
 */
// @SpringBootTest
// @Import(TrackingDatabaseClientConfig::class)
object SqlInjectionTestRunner {
    private val applicationContext: ApplicationContext? = null // main에서는 실제 ApplicationContext를 사용하지 않음
    
    /**
     * Scans all repositories in the given package for SQL injection vulnerabilities.
     * @param packageName The package name to scan (e.g., "com.skplanet.pcona.ad.repository")
     * @param applicationContext (optional) Spring ApplicationContext for bean injection
     * @return A list of vulnerability reports.
     */
    fun scanRepositories(packageName: String, applicationContext: ApplicationContext? = null): List<VulnerabilityReport> {
        // 1. Find all Repository classes in the given package
        val classLoader = Thread.currentThread().contextClassLoader
        val repoClasses = findRepositoryClasses(packageName, classLoader)
        println("[DEBUG] Found repository classes: " + repoClasses.map { it.qualifiedName })
        
        val results = mutableListOf<RepositoryScanResult>()
        
        // 2. Scan each repository for vulnerabilities
        for (repoClass in repoClasses) {
            val repoName = repoClass.simpleName ?: "<unknown>"
            println("[DEBUG] Scanning repository: $repoName")
            val vulnerabilities = scanRepository(repoClass, applicationContext)
            println("[DEBUG] -> Vulnerabilities found: ${vulnerabilities.size}")
            results.add(RepositoryScanResult(repoName, vulnerabilities.size, vulnerabilities))
        }
        
        // 3. Report results
        val reporter = SecurityScanReporter(results)
        reporter.printReport()
        
        // 4. Return all found vulnerabilities
        return results.flatMap { it.vulnerabilities }
    }
    
    private fun findRepositoryClasses(packageName: String, classLoader: ClassLoader): List<KClass<*>> {
        val path = packageName.replace('.', '/')
        val repoClasses = mutableListOf<KClass<*>>()
        
        val resources = classLoader.getResources(path)
        while (resources.hasMoreElements()) {
            val url = resources.nextElement()
            if (url.protocol != "jar") {
                val dir = java.io.File(url.toURI())
                dir.walk()
                    .filter { it.isFile && it.name.endsWith(".class") }
                    .forEach { file ->
                        val relativePath = file.relativeTo(dir).path.replace('/', '.').removeSuffix(".class")
                        val fqcn = if (relativePath.startsWith(packageName)) relativePath else "$packageName.$relativePath"
                        try {
                            val clazz = Class.forName(fqcn).kotlin
                            if (clazz.annotations.any { it.annotationClass.simpleName == "Repository" }) {
                                repoClasses.add(clazz)
                            }
                        } catch (_: Throwable) { }
                    }
            }
        }
        return repoClasses
    }
    
    private fun scanRepository(repoClass: KClass<*>, applicationContext: ApplicationContext?): List<VulnerabilityReport> {
        val vulnerabilities = mutableListOf<VulnerabilityReport>()
        val publicMethods = repoClass.declaredFunctions
            .filter { it.visibility == kotlin.reflect.KVisibility.PUBLIC }
        println("[DEBUG] Public methods in ${repoClass.simpleName}: ${publicMethods.map { it.name }}")
        
        for (method in publicMethods) {
            // Clear tracking before each method test
            TrackingDatabaseClientConfig.globalBoundParameters.clear()
            
            try {
                // Create dummy parameters and test the method
                val params = method.parameters.drop(1).map { param ->
                    DummyValueFactory.createDummyValue(param.type, applicationContext)
                }.toTypedArray()
                
                // Try to execute the method
                val instance = createRepositoryInstance(repoClass, applicationContext)
                method.call(instance, *params)
                
                // Check bound parameters
                val boundParams = TrackingDatabaseClientConfig.globalBoundParameters.toSet()
                val boundParamNames = boundParams.map { it.name }.toSet()
                
                // Check for unbounded parameters
                val methodParams = method.parameters.mapNotNull { it.name }
                val unboundParams = methodParams.filter { param ->
                    param.lowercase().replace("_", "") !in 
                        boundParamNames.map { it.lowercase().replace("_", "") }
                }
                
                if (unboundParams.isNotEmpty()) {
                    // Perform AST analysis for unbounded parameters
                    val qualifiedName = repoClass.qualifiedName
                    require(qualifiedName != null) { "Repository class must have a qualifiedName" }
                    
                    val mainPath = "src/main/kotlin/" + qualifiedName.replace('.', '/') + ".kt"
                    val testPath = "src/test/kotlin/" + qualifiedName.replace('.', '/') + ".kt"
                    
                    val repoFile = when {
                        java.io.File(mainPath).exists() -> mainPath
                        java.io.File(testPath).exists() -> testPath
                        else -> null
                    }
                    
                    println("[DEBUG] Performing AST analysis for ${repoClass.simpleName}.${method.name} (unbound params: $unboundParams, file: $repoFile)")

                    if (repoFile != null) {
                        val astVulns = SqlInjectionAstAnalyzer.analyzeFile(
                            repoFile,
                            repoClass.simpleName ?: "<unknown>",
                            method.name,
                            methodParams,
                            unboundParams
                        )
                        vulnerabilities.addAll(astVulns)
                    }
                }
            } catch (e: Throwable) {
                println("[DEBUG] Exception in method '\u001B[31m${method.name}\u001B[0m' of ${repoClass.simpleName}: ${e::class.simpleName} - ${e.message}")
            }
        }
        
        return vulnerabilities
    }
    
    private fun createRepositoryInstance(repoClass: KClass<*>, applicationContext: ApplicationContext?): Any? {
        val ctor = repoClass.constructors.firstOrNull()
        val ctorParams = ctor?.parameters?.map { param ->
            DummyValueFactory.createDummyValue(param.type, applicationContext)
        }?.toTypedArray() ?: emptyArray()
        
        return try {
            ctor?.call(*ctorParams)
        } catch (_: Throwable) {
            null
        }
    }
} 