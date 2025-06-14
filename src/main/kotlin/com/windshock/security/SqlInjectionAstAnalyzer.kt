package com.windshock.security

import java.io.File
import java.io.BufferedReader
import java.io.FileReader
import org.antlr.v4.runtime.CharStreams
import org.antlr.v4.runtime.CommonTokenStream
import com.windshock.security.KotlinLexer
import com.windshock.security.KotlinParser
import org.antlr.v4.runtime.tree.ParseTree
import org.antlr.v4.runtime.Token

/**
 * SQL 인젝션 위험 탐지기 (Kotlin 전용)
 * - DatabaseClient.execute 호출부에서 쿼리 문자열이 문자열 결합 연산자로 위험한지 체크
 * - bind 호출이 없는 파라미터가 쿼리 문자열에 직접 포함되는지 탐지
 */
object SqlInjectionAstAnalyzer {
    fun analyzeFile(
        filePath: String,
        repoName: String,
        methodName: String,
        methodParams: List<String> = emptyList(), // 메서드 파라미터 이름 리스트
        paramsWithoutBind: List<String> = emptyList() // bind 미사용 파라미터 리스트
    ): List<VulnerabilityReport> {
        val file = File(filePath)
        if (!file.exists() || !file.isFile) return emptyList()

        try {
            // 파일 전체 소스코드 읽기
            val source = file.readText()
            val vulnerabilities = mutableListOf<VulnerabilityReport>()

            // 1. 토큰 기반 위험 탐지 (execute/sql, +, $, bind)
            val lexer: KotlinLexer = com.windshock.security.KotlinLexer(org.antlr.v4.runtime.CharStreams.fromString(source))
            val tokens: org.antlr.v4.runtime.CommonTokenStream = org.antlr.v4.runtime.CommonTokenStream(lexer)
            tokens.fill()
            val tokenTexts: MutableList<String> = mutableListOf<String>()
            for (token in tokens.getTokens()) {
                if (token is org.antlr.v4.runtime.Token) {
                    tokenTexts.add(token.text)
                }
            }

            val hasExecuteOrSql = tokenTexts.any { it.contains("execute") || it.contains("sql") }
            val hasPlusOrDollar = tokenTexts.any { it.contains("+") || it.contains("$") }
            val hasUnboundParameter = paramsWithoutBind.any { param -> tokenTexts.any { it.contains(param) } }

            // 안전 SQL 유틸 함수명 화이트리스트
            val safeSqlUtils: Set<String> = setOf(
                "Utils.toSql"
            )
            // 안전 유틸 함수만으로 쿼리 조립 시 과탐 방지
            val isSafeSqlConcat = tokenTexts.any { safeSqlUtils.any { util -> it.contains(util) } }

            val foundUnsafeByToken = hasExecuteOrSql && hasPlusOrDollar && hasUnboundParameter && !isSafeSqlConcat
            val tokenVulnMethodNames = mutableSetOf<String>()
            if (foundUnsafeByToken) {
                tokenVulnMethodNames.add(methodName)
                println("[DEBUG][AST] Token-based SQLi detected in $repoName.$methodName (params: $paramsWithoutBind)")
            }

            // 2. ParseTree 기반 위험 탐지
            val charStream2 = CharStreams.fromString(source)
            val lexer2 = KotlinLexer(charStream2)
            val tokenStream2 = CommonTokenStream(lexer2)
            val parser2 = KotlinParser(tokenStream2)
            val tree2 = parser2.kotlinFile()
            var currentClass = ""
            var currentMethod = ""
            val reported = mutableSetOf<String>()
            val parseTreeVulnMethodNames = mutableSetOf<String>()
            fun findUnsafeInParseTree(node: org.antlr.v4.runtime.tree.ParseTree?) {
                if (node == null) return
                // 클래스명 추적
                if (node.javaClass.simpleName == "ClassDeclarationContext") {
                    try {
                        val clazz = node.javaClass
                        val method = clazz.getMethod("simpleIdentifier")
                        val idNode = method.invoke(node)
                        if (idNode != null) {
                            val nameMethod = idNode.javaClass.getMethod("getText")
                            currentClass = nameMethod.invoke(idNode) as? String ?: ""
                        }
                    } catch (_: Exception) {}
                }
                // 함수명 추적
                if (node.javaClass.simpleName == "FunctionDeclarationContext") {
                    try {
                        val clazz = node.javaClass
                        val method = clazz.getMethod("simpleIdentifier")
                        val idNode = method.invoke(node)
                        if (idNode != null) {
                            val nameMethod = idNode.javaClass.getMethod("getText")
                            currentMethod = nameMethod.invoke(idNode) as? String ?: ""
                        }
                    } catch (_: Exception) {}
                }
                val text = node.text
                // ParseTree 내에서 안전 유틸 함수만 쓰인 경우 과탐 방지
                val isSafeSqlInTree = safeSqlUtils.any { util -> text.contains(util) }

                // paramsWithoutBind(바인딩 안 된 변수)만 실제 쿼리 문자열 내에 직접 삽입되는 경우만 탐지
                paramsWithoutBind.forEach { param ->
                    // 문자열 결합(+), 템플릿($), 직접 포함 여부, toString(), append()
                    val directConcat = Regex("""[+$][^a-zA-Z0-9_]*${Regex.escape(param)}""").containsMatchIn(text)
                    val templateUse = Regex("""\$${param}|\$\{${Regex.escape(param)}}""").containsMatchIn(text)
                    val directInsert = Regex("""["']\s*\+\s*${Regex.escape(param)}""").containsMatchIn(text)
                    val toStringConcat = Regex("""\+.*${Regex.escape(param)}.*toString""").containsMatchIn(text)
                    val appendUse = Regex("""append\s*\(\s*${Regex.escape(param)}\s*\)""").containsMatchIn(text)
                    if ((text.contains("execute") || text.contains("sql")) &&
                        (directConcat || templateUse || directInsert || toStringConcat || appendUse) && !isSafeSqlInTree) {
                        val uniqueKey = "${if (currentClass.isNotEmpty()) currentClass else "?"}.${if (currentMethod.isNotEmpty()) currentMethod else "?"}"
                        if (currentMethod.isNotEmpty()) {
                            parseTreeVulnMethodNames.add(currentMethod)
                            if (!reported.contains(uniqueKey)) {
                                println("[DEBUG][AST] ParseTree-based SQLi detected in $uniqueKey (param: $param)")
                                vulnerabilities.add(
                                    VulnerabilityReport(
                                        currentMethod,
                                        currentClass,
                                        RiskLevel.CRITICAL,
                                        "[ParseTree] $uniqueKey: execute/sql 호출에서 쿼리 문자열에 +/$ 등으로 바인딩 안 된 변수(${param}) 직접 삽입 감지"
                                    )
                                )
                                reported.add(uniqueKey)
                            }
                        }
                    }
                }
                for (i in 0 until node.childCount) {
                    findUnsafeInParseTree(node.getChild(i))
                }
            }
            findUnsafeInParseTree(tree2)

            // 교집합만 남기기
            val intersection = tokenVulnMethodNames.intersect(parseTreeVulnMethodNames)
            val filtered = vulnerabilities.filter { parseTreeVulnMethodNames.contains(it.methodName) }

            // WARNING 레벨 제외하고 반환
            println("[DEBUG][AST] Final vulnerabilities for $repoName.$methodName: ${filtered.map { it.methodName }}")
            return filtered.filter { it.riskLevel != RiskLevel.WARNING }
        } catch (e: Exception) {
            // 실패 시에도 WARNING은 리포트하지 않음
            return emptyList()
        }
    }
} 