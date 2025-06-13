package com.windshock.security

import com.windshock.security.SecurityScanReporter

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.AfterEach
import java.io.File
import kotlin.reflect.KClass
import kotlin.reflect.KType
import kotlin.reflect.KVisibility
import kotlin.reflect.full.*
import kotlin.reflect.jvm.jvmErasure
import com.windshock.security.DummyValueFactory
import com.windshock.security.RiskLevel
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit.jupiter.SpringExtension
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.context.annotation.Bean
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Import
import org.springframework.context.annotation.EnableAspectJAutoProxy
import org.junit.jupiter.api.BeforeEach



@org.springframework.boot.test.context.SpringBootTest
@org.springframework.context.annotation.Import(TrackingDatabaseClientConfig::class)
class AllRepositoriesBindingTest {

    @Autowired
    lateinit var applicationContext: ApplicationContext

    @Autowired
    lateinit var databaseClient: org.springframework.data.r2dbc.core.DatabaseClient

    @BeforeEach
    fun clearBindTracking() {
        TrackingDatabaseClientConfig.globalBoundParameters.clear()
    }

    @AfterEach
    fun reportBindTracking() {
        println("\n========== SQL BIND TRACKING REPORT ==========")
        if (TrackingDatabaseClientConfig.globalBoundParameters.isEmpty()) {
            println("❌ No binding tracking! (SQL injection risk)")
        } else {
            println("✅ Bound parameters:")
            TrackingDatabaseClientConfig.globalBoundParameters.forEach {
                val callerInfo = it.caller?.let { c -> "at ${c.className}.${c.methodName}:${c.lineNumber}" } ?: "(unknown caller)"
                println("    - ${it.name} = ${it.value} ($callerInfo)")
            }
        }
        println("============================================\n")
        // Purpose: Test fails when binding is missing
        // (testAopBindMissing is intentionally written to fail)
        // AOP/Aspect-based tracking has been removed. Only using DI-based TrackingDatabaseClient.
    }

    @Test
    fun testParameterBinding() {
        // 예외 분류 함수 정의
        fun classifyException(e: Throwable): Pair<RiskLevel, String> {
            // Common test environment exceptions are treated as WARNING
            return when (e) {
                is java.lang.IllegalArgumentException,
                is java.lang.UnsupportedOperationException,
                is java.lang.IllegalStateException,
                is java.lang.reflect.InvocationTargetException ->
                    RiskLevel.WARNING to "Test environment exception: ${e.javaClass.simpleName} - ${e.message}"
                else -> RiskLevel.CRITICAL to "Runtime exception: ${e.javaClass.simpleName} - ${e.message}"
            }
        }
        // 1. Find all Repository classes in the compiled output directory
        val classLoader = Thread.currentThread().contextClassLoader
        val repoClasses = mutableListOf<KClass<*>>()

        // Scan all classes in the classpath for @Repository annotation
        val packageNames = setOf("com.example", "org.springframework.data")
        packageNames.forEach { pkg ->
            val path = pkg.replace('.', '/')
            val resources = classLoader.getResources(path)
            while (resources.hasMoreElements()) {
                val url = resources.nextElement()
                if (url.protocol == "jar") {
                    val jarUrl = url.toString().substringAfter("jar:").substringBefore("!")
                    val jarFile = File(jarUrl)
                    // JAR 파일 내부 리소스 처리
                    // TODO: JAR 파일 내부 리소스 처리 로직 추가
                } else {
                    val dir = File(url.toURI())
                    dir.walk()
                        .filter { it.isFile && it.name.endsWith(".class") }
                        .forEach { file ->
                            val relativePath = file.relativeTo(dir).path.replace('/', '.').removeSuffix(".class")
                            val fqcn = "$pkg.$relativePath"
                            try {
                                val clazz = Class.forName(fqcn).kotlin
                                if (clazz.annotations.any { it.annotationClass.simpleName == "Repository" }) {
                                    repoClasses.add(clazz)
                                }
                            } catch (_: Throwable) { }
                        }
                }
            }
        }
        val results = mutableListOf<RepositoryScanResult>()
        for (repoKClass in repoClasses) {
            val repoName = repoKClass.simpleName ?: "<unknown>"
            val vulnerabilities = mutableListOf<VulnerabilityReport>()
            val ctor = repoKClass.constructors.firstOrNull()
            val ctorParams = ctor?.parameters?.map { param ->
                val value = DummyValueFactory.createDummyValue(param.type, applicationContext)
                if (!param.type.isMarkedNullable && value == null) {
                    when (param.type.jvmErasure) {
                        Int::class -> 0
                        Long::class -> 0L
                        Double::class -> 0.0
                        String::class -> ""
                        else -> throw IllegalArgumentException("Cannot create dummy for non-nullable type: "+param.type)
                    }
                } else value
            }?.toTypedArray() ?: emptyArray()
            val repoInstance = try { ctor?.call(*ctorParams) } catch (e: Throwable) { null }
            val publicMethods = repoKClass.declaredFunctions.filter { it.visibility == KVisibility.PUBLIC }
            for (method in publicMethods) {
                val paramNames = method.parameters.drop(1).map { it.name ?: "" }
                val params = method.parameters.drop(1).map { param ->
                    when (param.type.jvmErasure) {
                        Int::class -> 0
                        Long::class -> 0L
                        Double::class -> 0.0
                        String::class -> ""
                        else -> "dummy"
                    }
                }.toTypedArray()
                // 1. AOP 기반 파라미터 추적: 실행 전 초기화
                TrackingDatabaseClientConfig.globalBoundParameters.clear()
                try {
                    method.call(repoInstance, *params)
                } catch (_: Throwable) { /* 예외 무시, 취약점 탐지 목적 */ }
                // 2. bind 호출된 파라미터 이름 추출
                val boundParams = TrackingDatabaseClientConfig.globalBoundParameters.toSet()
                val boundParamNames = boundParams.map { it.name }.toSet()
                // 함수 정의에서 파라미터 이름 추출 (Kotlin reflection)
                val methodParams = method.parameters.mapNotNull { it.name }
                // normalize 함수: 언더스코어 제거, 소문자화
                fun normalize(name: String) = name.replace("_", "").lowercase()
                val paramsWithoutBind = methodParams.filter { p ->
                    normalize(p) !in boundParamNames.map(::normalize)
                }
                // AST 기반 정적 분석
                val qualifiedName = repoKClass.qualifiedName
                require(qualifiedName != null) { "Repository class must have a qualifiedName" }
                val mainPath = "src/main/kotlin/" + qualifiedName.replace('.', '/') + ".kt"
                val testPath = "src/test/kotlin/" + qualifiedName.replace('.', '/') + ".kt"
                val repoFile: String? = when {
                    java.io.File(mainPath).exists() -> mainPath
                    java.io.File(testPath).exists() -> testPath
                    else -> null
                }
                // 바인딩 누락된 파라미터가 있을 때, 해당 파라미터가 실제로 문자열 연산("+", $ 등) 또는 취약하게 사용되는지 AST로 추가 분석
                if (paramsWithoutBind.isNotEmpty()) {
                    val astVulns = if (repoFile != null) {
                        SqlInjectionAstAnalyzer.analyzeFile(
                            repoFile,
                            repoName,
                            method.name,
                            paramNames,
                            paramsWithoutBind
                        )
                    } else emptyList()
                    if (astVulns.isNotEmpty()) {
                        vulnerabilities.addAll(astVulns)
                    }
                }
            }
            results.add(RepositoryScanResult(repoName, publicMethods.size, vulnerabilities))
        }
        val reporter = SecurityScanReporter(results)
        reporter.printReport()
        if (reporter.hasVulnerabilities()) {
            throw AssertionError(reporter.getErrorMessage())
        }
    }
} // ← 클래스 선언부를 반드시 닫는다!!

// 클래스 선언 이후에만 외부 함수 선언

